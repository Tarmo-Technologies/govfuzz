// SPDX-License-Identifier: Apache-2.0

//! Mine construction recipes out of the directories discovery deliberately skips.
//!
//! `tests/`, `examples/` and `benchmarks/` are excluded as fuzz TARGETS, and
//! rightly so — a test is not an attack surface. But those files are the one
//! place in a project where somebody has already written down how to build the
//! very objects a harness cannot: the opaque handle, the parser needing a
//! configured context, the class with no default constructor.
//!
//! So they are read here as a RECIPE source rather than a target source. Only
//! self-contained constructions are usable: an expression built from literals
//! compiles anywhere, while one referring to a test's local variables or
//! fixtures does not, and a recipe that does not compile is worse than none.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Directory names that hold example code rather than shipped API. Matches the
/// discovery exclusion list, since the point is to read exactly what discovery
/// refuses to treat as a target.
const RECIPE_DIRS: &[&str] = &[
    "test",
    "tests",
    "testing",
    "example",
    "examples",
    "sample",
    "samples",
    "bench",
    "benches",
    "benchmark",
    "benchmarks",
    "demo",
    "demos",
];

/// Maintained fuzz targets are the strongest protocol evidence in a project:
/// unlike a unit test, their call sequence has already been chosen for broad,
/// input-driven reachability. They are not construction-recipe directories
/// (most arguments name the fuzzer input), but they are included when mining
/// ordered call traces below.
const FUZZ_DIRS: &[&str] = &["fuzz", "fuzzer", "fuzzers", "oss-fuzz"];

/// Cap on files read. A recipe is a nice-to-have; it must never turn harness
/// generation into a whole-repository scan.
const MAX_FILES: usize = 400;
/// Cap on the size of any single file read, for the same reason.
const MAX_FILE_BYTES: u64 = 512 * 1024;

/// Class leaf name -> a self-contained construction expression for it.
pub(crate) type MinedRecipes = BTreeMap<String, String>;

/// Recipes for the project owning `source_path`, mined once per project.
///
/// Both the preflight ("is this parameter blocked?") and generation ("build it
/// like this") must see the SAME recipes, or a target is pre-skipped as
/// unbuildable and then turns out to be buildable, or worse the reverse. Deriving
/// the root from the source and caching by that root makes them agree by
/// construction rather than by two call sites being kept in step.
///
/// Shared by `Arc`, not cloned. The map holds one entry per constructible class
/// in the project, and handing out a copy made a cache HIT cost as much as a
/// small mine: 2,863 calls (one per function in simdjson's amalgamated `.cpp`)
/// spent **133 of the preflight's 137 seconds** copying it, which is what made
/// discovery on an amalgamated header never finish.
pub(crate) fn for_source(source_path: &Path) -> std::sync::Arc<MinedRecipes> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<std::path::PathBuf, std::sync::Arc<MinedRecipes>>>,
    > = std::sync::OnceLock::new();
    let Some(root) = project_root_of(source_path) else {
        return std::sync::Arc::new(MinedRecipes::new());
    };
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(hit) = guard.get(&root) {
            return std::sync::Arc::clone(hit);
        }
    }
    let mined = std::sync::Arc::new(mine(&root, &["cpp", "cc", "cxx", "c", "hpp", "h"]));
    if let Ok(mut guard) = cache.lock() {
        guard.insert(root, std::sync::Arc::clone(&mined));
    }
    mined
}

/// The nearest ancestor of `source_path` that actually contains an example-ish
/// directory. Bounded, so a source deep in a tree cannot walk to the filesystem
/// root looking for one.
pub(crate) fn project_root_of(source_path: &Path) -> Option<std::path::PathBuf> {
    let mut current = source_path.parent()?;
    let mut manifest_root = None;
    for _ in 0..8 {
        if !recipe_dirs_directly_under(current).is_empty()
            || !named_dirs_directly_under(current, FUZZ_DIRS).is_empty()
        {
            return Some(current.to_path_buf());
        }
        // Some mature projects keep their maintained examples/tests directly
        // in the repository root (TinyXML2's `xmltest.cpp` is a representative
        // case). Remember the nearest unambiguous project boundary so those
        // files can still supply recipes without walking an arbitrary parent
        // tree or treating the library implementation itself as test evidence.
        if manifest_root.is_none() && has_project_root_marker(current) {
            manifest_root = Some(current.to_path_buf());
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }
    manifest_root
}

fn has_project_root_marker(dir: &Path) -> bool {
    [
        ".git",
        "Cargo.toml",
        "CMakeLists.txt",
        "meson.build",
        "configure.ac",
        "configure.in",
        "go.mod",
        "pyproject.toml",
    ]
    .iter()
    .any(|marker| dir.join(marker).exists())
}

fn recipe_dirs_directly_under(dir: &Path) -> Vec<std::path::PathBuf> {
    named_dirs_directly_under(dir, RECIPE_DIRS)
}

fn named_dirs_directly_under(dir: &Path, names: &[&str]) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter(|entry| {
            names.contains(
                &entry
                    .file_name()
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .as_str(),
            )
        })
        .map(|entry| entry.path())
        .collect()
}

/// Read every example-ish source under `root` and extract the constructions they
/// contain.
pub(crate) fn mine(root: &Path, extensions: &[&str]) -> MinedRecipes {
    let mut out = MinedRecipes::new();
    let mut budget = MAX_FILES;
    for dir in recipe_dirs(root) {
        for file in source_files(&dir, extensions, &mut budget) {
            if let Ok(text) = std::fs::read_to_string(&file) {
                if recipe_text_is_visible(&text) {
                    merge(&mut out, mine_text(&text));
                }
            }
        }
    }
    for file in root_recipe_source_files(root, extensions, &mut budget) {
        if let Ok(text) = std::fs::read_to_string(&file) {
            if recipe_text_is_visible(&text) {
                merge(&mut out, mine_text(&text));
            }
        }
    }
    out
}

fn merge(into: &mut MinedRecipes, from: MinedRecipes) {
    for (class, expr) in from {
        // Prefer the SHORTEST construction seen. Fewer arguments means fewer ways
        // to be wrong about what the project considers a valid object, and a
        // shorter expression is likelier to be literal-only.
        match into.get(&class) {
            Some(existing) if existing.len() <= expr.len() => {}
            _ => {
                into.insert(class, expr);
            }
        }
    }
}

fn recipe_dirs(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(dir) = stack.pop() {
        visited += 1;
        if visited > 2_000 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name.starts_with('.') {
                continue;
            }
            if RECIPE_DIRS.contains(&name.as_str()) {
                found.push(path);
            } else {
                stack.push(path);
            }
        }
    }
    found
}

fn source_files(dir: &Path, extensions: &[&str], budget: &mut usize) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            if *budget == 0 {
                return files;
            }
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let matches = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| extensions.contains(&ext));
            if !matches {
                continue;
            }
            if entry.metadata().map(|m| m.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
                continue;
            }
            files.push(path);
            *budget -= 1;
        }
    }
    files
}

/// Maintained test/example sources sometimes live directly beside the build
/// manifest instead of under `tests/` or `examples/`. Limit this fallback to
/// conspicuously recipe-like filenames; recursively scanning the project root
/// would mistake implementation-internal calls for an expert workflow.
fn root_recipe_source_files(
    root: &Path,
    extensions: &[&str],
    budget: &mut usize,
) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for entry in entries.flatten() {
        if *budget == 0 {
            break;
        }
        let path = entry.path();
        if !path.is_file()
            || !path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extensions.contains(&extension))
            || entry.metadata().map(|meta| meta.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES
        {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !["test", "spec", "example", "sample", "demo", "bench", "fuzz"]
            .iter()
            .any(|hint| stem.contains(hint))
        {
            continue;
        }
        files.push(path);
        *budget -= 1;
    }
    files.sort();
    files
}

/// Extract `Class(...)` construction expressions from one source text.
///
/// Two shapes carry a usable recipe:
///   `Widget w(3, "name");`      -> `Widget(3, "name")`
///   `Widget w = Widget::of(7);` -> `Widget::of(7)`
///
/// Both are accepted only when every argument is a literal. A construction
/// naming a local variable cannot be lifted out of the test it lives in.
pub(crate) fn mine_text(text: &str) -> MinedRecipes {
    let mut out = MinedRecipes::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("//") || line.starts_with('*') || line.starts_with('#') {
            continue;
        }
        if let Some((class, expr)) = mine_line(line) {
            merge(&mut out, BTreeMap::from([(class, expr)]));
        }
    }
    out
}

fn mine_line(line: &str) -> Option<(String, String)> {
    let statement = line.strip_suffix(';')?.trim();
    // `Class name = <expr>` — the assigned expression is used verbatim, so it
    // must name the class to be a construction of it rather than a conversion.
    if let Some((decl, rhs)) = statement.split_once('=') {
        let rhs = rhs.trim();
        let class = declared_class(decl.trim())?;
        if rhs.starts_with(&class) && rhs.ends_with(')') && literal_arguments(rhs) {
            return Some((class, rhs.to_owned()));
        }
        return None;
    }
    // `Class name(args)` — direct initialization.
    let open = statement.find('(')?;
    if !statement.ends_with(')') {
        return None;
    }
    let class = declared_class(statement[..open].trim())?;
    let args = &statement[open..];
    if !literal_arguments(statement) {
        return None;
    }
    // A declaration, not a call: `Class name(...)` has a name between the class
    // and the parenthesis. Without it this is `Class(...)`, an expression
    // statement, which says nothing about how to build a named object.
    Some((class.clone(), format!("{class}{args}")))
}

/// The class of a `Class name` declaration head, if it looks like one.
fn declared_class(head: &str) -> Option<String> {
    let mut words: Vec<&str> = head.split_whitespace().collect();
    // Drop declaration noise that does not change the constructed type.
    words.retain(|w| !matches!(*w, "const" | "static" | "auto" | "inline" | "constexpr"));
    if words.len() != 2 {
        return None;
    }
    let class = words[0];
    let name = words[1];
    if !is_identifier_like(class) || !is_plain_identifier(name) {
        return None;
    }
    // A pointer or reference declaration does not construct a value.
    if class.ends_with('*') || class.ends_with('&') {
        return None;
    }
    // Primitive types need no recipe and would only add noise.
    const PRIMITIVES: &[&str] = &[
        "int", "unsigned", "long", "short", "char", "float", "double", "bool", "size_t", "void",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t",
    ];
    if PRIMITIVES.contains(&class) {
        return None;
    }
    Some(class.to_owned())
}

fn is_identifier_like(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
        && text.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
}

fn is_plain_identifier(text: &str) -> bool {
    !text.is_empty()
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && text.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
}

/// Whether every argument inside the LAST parenthesised group is a literal.
///
/// This is the whole safety property: an expression built from literals can be
/// lifted into a harness, while one naming a test's local variable, fixture, or
/// helper cannot and would not compile.
fn literal_arguments(expr: &str) -> bool {
    let Some(open) = expr.find('(') else {
        return false;
    };
    let Some(close) = expr.rfind(')') else {
        return false;
    };
    if close <= open {
        return false;
    }
    let inner = expr[open + 1..close].trim();
    if inner.is_empty() {
        return true;
    }
    split_arguments(inner).iter().all(|arg| is_literal(arg))
}

/// Split on top-level commas so a nested call or braced list stays one argument.
fn split_arguments(inner: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for ch in inner.chars() {
        if in_string {
            current.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                current.push(ch);
            }
            '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                args.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        args.push(current);
    }
    args
}

fn is_literal(arg: &str) -> bool {
    let arg = arg.trim().trim_start_matches('-').trim();
    if arg.is_empty() {
        return false;
    }
    if arg.starts_with('"') && arg.ends_with('"') && arg.len() >= 2 {
        return true;
    }
    if arg.starts_with('\'') && arg.ends_with('\'') && arg.len() >= 2 {
        return true;
    }
    if matches!(arg, "true" | "false" | "nullptr" | "NULL" | "0") {
        return true;
    }
    // A number, with optional suffix/decimal point.
    let mut chars = arg.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_digit()) {
        return false;
    }
    arg.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == 'x' || c == 'X')
}

/// Ordered call evidence mined from the same test/example sources.
///
/// A recipe says how to BUILD a value. It says nothing about ORDER, and order is
/// most of what a stateful API's contract is: zlib's own `test_flush` spells
/// `deflateInit` -> `deflate` -> `deflateEnd`, libarchive's tests spell
/// `archive_read_new` -> `archive_read_open_memory` -> `archive_read_next_header`.
/// Generated sequences ordered ops by declaration line, which is arbitrary with
/// respect to the contract.
///
/// The evidence is deliberately weak and local: ordered pairs observed on the
/// SAME first argument inside one file. It is used to prefer an order, never to
/// forbid one, so a wrong guess costs ordering quality and not reachability.
pub(crate) type CallOrder = BTreeMap<(String, String), usize>;

/// Extract ordered `(earlier, later)` call pairs that share a first argument.
///
/// The shared first argument is what makes this evidence about ONE object's
/// lifecycle rather than about two unrelated calls that happen to be adjacent.
pub(crate) fn mine_call_order(text: &str) -> CallOrder {
    let mut per_receiver: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("//") || line.starts_with('*') || line.starts_with('#') {
            continue;
        }
        for (name, receiver) in calls_in_line(line) {
            per_receiver.entry(receiver).or_default().push(name);
        }
    }
    let mut order = CallOrder::new();
    for calls in per_receiver.values() {
        // Every ordered pair, not just adjacent ones: `deflateInit` precedes
        // `deflateEnd` in zlib's own test even though a `deflate` sits between
        // them, and that is exactly the constraint worth knowing.
        for (i, earlier) in calls.iter().enumerate() {
            for later in calls.iter().skip(i + 1) {
                if earlier == later {
                    continue;
                }
                *order.entry((earlier.clone(), later.clone())).or_insert(0) += 1;
            }
        }
    }
    order
}

/// `name(arg0, ...)` occurrences in a line, paired with the first argument's
/// leading identifier (with any `&` / `*` stripped).
fn calls_in_line(line: &str) -> Vec<(String, String)> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut index = 0usize;
    while let Some(open) = line[index..].find('(').map(|at| at + index) {
        let name_end = open;
        let mut name_start = name_end;
        while name_start > 0 {
            let ch = bytes[name_start - 1] as char;
            if ch.is_ascii_alphanumeric() || ch == '_' {
                name_start -= 1;
            } else {
                break;
            }
        }
        let name = &line[name_start..name_end];
        // Skip control keywords, which take a parenthesis but are not calls.
        let is_keyword = matches!(
            name,
            "if" | "for" | "while" | "switch" | "return" | "sizeof" | ""
        );
        if !is_keyword {
            let rest = &line[open + 1..];
            let first_arg = rest
                .split([',', ')'])
                .next()
                .unwrap_or("")
                .trim()
                .trim_start_matches(['&', '*'])
                .trim();
            let receiver: String = first_arg
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !receiver.is_empty() && !receiver.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                out.push((name.to_owned(), receiver));
            }
        }
        index = open + 1;
    }
    out
}

/// One API call observed in project-owned protocol code. Arguments are kept as
/// source spellings for the caller to classify against the proven declaration;
/// they are never emitted verbatim unless [`safe_protocol_literal`] accepts
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MinedProtocolCall {
    pub(crate) name: String,
    /// The root lifecycle object reached through the first argument. For a
    /// direct call this is the first argument itself; for a dependent call such
    /// as `describe(get_error(parser))`, it is recursively `parser`.
    pub(crate) receiver: String,
    pub(crate) receiver_is_direct: bool,
    pub(crate) arguments: Vec<String>,
    pub(crate) assigned_to: Option<String>,
    /// Exact call spelling used only to match a nested argument to a previously
    /// declaration-checked result. It is never emitted as source.
    pub(crate) source_expression: String,
    /// A simple control dependency enclosing this call. The dependency names
    /// the earlier API call whose result was compared, rather than retaining an
    /// arbitrary C expression. The CLI still declaration-checks the producer
    /// and codegen only accepts a bounded comparison/value grammar.
    pub(crate) condition: Option<MinedProtocolCondition>,
    /// Bounded predicate over the fuzz-input length, such as Expat's
    /// `if (size % 2) XML_ParserReset(...)`.
    pub(crate) input_condition: Option<MinedProtocolInputCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MinedProtocolCondition {
    pub(crate) producer_name: String,
    pub(crate) producer_receiver: String,
    pub(crate) bitmask: Option<String>,
    pub(crate) comparison: MinedProtocolComparison,
    pub(crate) value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MinedProtocolComparison {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MinedProtocolInputSource {
    Size { input_name: String },
    Byte { input_name: String, index: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MinedProtocolInputTransform {
    Identity,
    Modulo(u64),
    BitAnd(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MinedProtocolInputCondition {
    pub(crate) source: MinedProtocolInputSource,
    pub(crate) transform: MinedProtocolInputTransform,
    pub(crate) comparison: MinedProtocolComparison,
    pub(crate) value: String,
}

/// An ordered call trace on one receiver variable. Keeping traces separate is
/// the central safety property: calls on two unrelated objects are never
/// stitched into a made-up state machine.
pub(crate) type MinedProtocolTrace = Vec<MinedProtocolCall>;

/// A public aggregate field assignment observed before a maintained call to the
/// selected endpoint. Only identifier fields and self-contained public
/// constants/literals are retained; codegen independently verifies that the
/// selected handle type actually declares the field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MinedCFieldInitializer {
    pub(crate) field: String,
    pub(crate) value: String,
}

/// Evidence for the common pull-parser protocol
/// `while (parse(handle, &output)) { inspect output; delete(&output); }`.
/// The CLI still declaration-checks every type/name before codegen uses it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MinedCOutputDrainProtocol {
    /// Parameter index after the lifecycle receiver.
    pub(crate) output_argument: usize,
    pub(crate) cleanup_name: String,
    pub(crate) terminal_field: String,
    pub(crate) terminal_value: String,
}

/// One declaration-independent C++ member call observed in a maintained test or
/// fuzz target. The CLI admits it only after matching the member name, arity,
/// declaring class, visibility, and parameter types against parsed declarations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MinedCppProtocolCall {
    pub(crate) receiver: String,
    pub(crate) name: String,
    pub(crate) arguments: Vec<String>,
}

pub(crate) type MinedCppProtocolTrace = Vec<MinedCppProtocolCall>;

/// Ordered C++ member-call traces for the project owning `source_path`.
/// Scoping is per function, so two tests that both call their object `parser`
/// can never be combined into a protocol neither test actually executed.
pub(crate) fn cpp_protocol_traces_for(source_path: &Path) -> Vec<MinedCppProtocolTrace> {
    language_method_protocol_traces_for(source_path, &["cc", "cpp", "cxx", "h", "hpp"])
}

pub(crate) fn rust_protocol_traces_for(source_path: &Path) -> Vec<MinedCppProtocolTrace> {
    language_method_protocol_traces_for(source_path, &["rs"])
}

fn language_method_protocol_traces_for(
    source_path: &Path,
    extensions: &[&str],
) -> Vec<MinedCppProtocolTrace> {
    type MethodProtocolCache =
        std::sync::Mutex<BTreeMap<(std::path::PathBuf, String), Vec<MinedCppProtocolTrace>>>;
    static CACHE: std::sync::OnceLock<MethodProtocolCache> = std::sync::OnceLock::new();
    let Some(root) = project_root_of(source_path) else {
        return Vec::new();
    };
    let cache_key = (root.clone(), extensions.join(","));
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(hit) = guard.get(&cache_key) {
            return hit.clone();
        }
    }

    let mut traces = Vec::new();
    let mut budget = MAX_FILES;
    let mut dirs = named_dirs_recursive(&root, FUZZ_DIRS);
    dirs.extend(recipe_dirs(&root));
    for dir in dirs {
        for file in source_files(&dir, extensions, &mut budget) {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            if !recipe_text_is_visible(&text) {
                continue;
            }
            traces.extend(mine_cpp_protocol_traces(&text));
        }
    }
    for file in root_recipe_source_files(&root, extensions, &mut budget) {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        if !recipe_text_is_visible(&text) {
            continue;
        }
        traces.extend(mine_cpp_protocol_traces(&text));
    }
    // Prefer the smallest complete observed workflow for method receivers. It
    // carries the least fixture state and the fewest values that would need to
    // be synthesized outside their original test. Stateful setup/target/finish
    // traces still win when no narrower valid workflow exists.
    traces.sort_by_key(Vec::len);
    if let Ok(mut guard) = cache.lock() {
        guard.insert(cache_key, traces.clone());
    }
    traces
}

pub(crate) fn mine_cpp_protocol_traces(text: &str) -> Vec<MinedCppProtocolTrace> {
    let clean = strip_c_comments(text);
    let functions = protocol_functions(&clean);
    let mut traces = if functions.is_empty() {
        cpp_method_call_traces(&clean)
    } else {
        functions
            .iter()
            .flat_map(|function| cpp_method_call_traces(function.body))
            .collect()
    };
    let definitions = protocol_constant_definitions(&clean);
    for trace in &mut traces {
        for call in trace {
            for argument in &mut call.arguments {
                if let Some(value) = fold_protocol_constant(argument, &definitions, 0) {
                    *argument = value;
                }
            }
        }
    }
    traces.retain(|trace| trace.len() >= 2);
    traces
}

#[derive(Debug)]
struct PositionedCppMethodCall {
    offset: usize,
    call: MinedCppProtocolCall,
}

/// Split calls not only by function and receiver spelling, but by the receiver's
/// lexical declaration. Large C++ test programs commonly put hundreds of cases
/// in one `main` and reuse a local name such as `doc` in each nested block. A
/// function-only grouping silently stitched those unrelated object lifetimes
/// into one fictional protocol.
fn cpp_method_call_traces(text: &str) -> Vec<MinedCppProtocolTrace> {
    let calls = cpp_method_calls(text);
    let receivers = calls
        .iter()
        .map(|positioned| positioned.call.receiver.clone())
        .collect::<BTreeSet<_>>();
    let declarations = receivers
        .into_iter()
        .map(|receiver| {
            let positions = cpp_receiver_declarations(text, &receiver);
            (receiver, positions)
        })
        .collect::<BTreeMap<_, _>>();
    let mut grouped = BTreeMap::<(String, Option<usize>), MinedCppProtocolTrace>::new();
    for positioned in calls {
        let receiver = positioned.call.receiver.clone();
        let declaration = declarations.get(&receiver).and_then(|positions| {
            positions
                .iter()
                .copied()
                .take_while(|p| *p < positioned.offset)
                .last()
        });
        grouped
            .entry((receiver, declaration))
            .or_default()
            .push(positioned.call);
    }
    grouped.into_values().collect()
}

fn cpp_method_calls(text: &str) -> Vec<PositionedCppMethodCall> {
    let bytes = text.as_bytes();
    let mut calls = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if !(bytes[index] as char).is_ascii_alphabetic() && bytes[index] != b'_' {
            index += 1;
            continue;
        }
        let receiver_start = index;
        index += 1;
        while index < bytes.len()
            && ((bytes[index] as char).is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        let receiver = &text[receiver_start..index];
        let mut separator = index;
        while separator < bytes.len() && (bytes[separator] as char).is_ascii_whitespace() {
            separator += 1;
        }
        let separator_len = if bytes.get(separator) == Some(&b'.') {
            1
        } else if bytes.get(separator..separator + 2) == Some(b"->") {
            2
        } else {
            continue;
        };
        let mut name_start = separator + separator_len;
        while name_start < bytes.len() && (bytes[name_start] as char).is_ascii_whitespace() {
            name_start += 1;
        }
        if name_start >= bytes.len()
            || (!(bytes[name_start] as char).is_ascii_alphabetic() && bytes[name_start] != b'_')
        {
            continue;
        }
        let mut name_end = name_start + 1;
        while name_end < bytes.len()
            && ((bytes[name_end] as char).is_ascii_alphanumeric() || bytes[name_end] == b'_')
        {
            name_end += 1;
        }
        let mut open = name_end;
        while open < bytes.len() && (bytes[open] as char).is_ascii_whitespace() {
            open += 1;
        }
        if bytes.get(open) != Some(&b'(') {
            continue;
        }
        let Some(close) = matching_paren(text, open) else {
            continue;
        };
        calls.push(PositionedCppMethodCall {
            offset: receiver_start,
            call: MinedCppProtocolCall {
                receiver: receiver.to_owned(),
                name: text[name_start..name_end].to_owned(),
                arguments: split_arguments(&text[open + 1..close])
                    .into_iter()
                    .map(|argument| argument.trim().to_owned())
                    .collect(),
            },
        });
        index = close + 1;
    }
    calls
}

fn cpp_receiver_declarations(text: &str, receiver: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = text[offset..].find(receiver) {
        let start = offset + relative;
        let end = start + receiver.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        if before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            || after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            offset = end;
            continue;
        }
        let suffix = text[end..].trim_start();
        if !suffix
            .chars()
            .next()
            .is_some_and(|ch| matches!(ch, ';' | '=' | '{' | '[' | '(' | ',' | ')'))
        {
            offset = end;
            continue;
        }
        let prefix_start = text[..start]
            .char_indices()
            .rev()
            .find(|(_, ch)| matches!(ch, ';' | '{' | '}' | '(' | ','))
            .map_or(0, |(index, ch)| index + ch.len_utf8());
        let prefix = text[prefix_start..start].trim();
        let lower = prefix.to_ascii_lowercase();
        let looks_like_type = !prefix.is_empty()
            && prefix.chars().any(|ch| ch.is_ascii_alphabetic())
            && !prefix.contains('=')
            && !prefix.contains('.')
            && !prefix.contains("->")
            && ![
                "return", "if", "while", "switch", "case", "delete", "throw", "sizeof",
            ]
            .contains(&lower.as_str());
        if looks_like_type {
            positions.push(start);
        }
        offset = end;
    }
    positions
}

/// Protocol traces for the project owning `source_path`, cached per project.
/// Fuzz targets are scanned before tests/examples so a maintained harness wins
/// ties over a narrow assertion-oriented test.
pub(crate) fn protocol_traces_for(source_path: &Path) -> Vec<MinedProtocolTrace> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<std::path::PathBuf, Vec<MinedProtocolTrace>>>,
    > = std::sync::OnceLock::new();
    let Some(root) = project_root_of(source_path) else {
        return Vec::new();
    };
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(hit) = guard.get(&root) {
            return hit.clone();
        }
    }

    let mut traces = Vec::new();
    let mut budget = MAX_FILES;
    let mut dirs = named_dirs_recursive(&root, FUZZ_DIRS);
    dirs.extend(recipe_dirs(&root));
    for dir in dirs {
        for file in source_files(&dir, &["c", "cc", "cpp", "cxx", "h", "hpp"], &mut budget) {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            if !recipe_text_is_visible(&text) {
                continue;
            }
            traces.extend(mine_protocol_traces(&text));
        }
    }
    for file in root_recipe_source_files(&root, &["c", "cc", "cpp", "cxx", "h", "hpp"], &mut budget)
    {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        if !recipe_text_is_visible(&text) {
            continue;
        }
        traces.extend(mine_protocol_traces(&text));
    }
    // Prefer richer traces. Selection still requires a requested target and
    // declaration/type matches, so length is only a quality tiebreaker.
    traces.sort_by_key(|trace| std::cmp::Reverse(trace.len()));
    if let Ok(mut guard) = cache.lock() {
        guard.insert(root, traces.clone());
    }
    traces
}

/// Mine required public struct preconditions from maintained examples/tests.
///
/// A zeroed aggregate is not always a valid API object. libpng, for example,
/// requires `png_image.version = PNG_IMAGE_VERSION` before every simplified
/// read entrypoint and otherwise rejects the input before parsing a byte. This
/// recovers that general shape without copying arbitrary setup code: the
/// assignment must be in the same function, precede the selected call on the
/// same receiver, and use a literal or uppercase public constant. Conflicting
/// values for one field are discarded rather than guessed.
pub(crate) fn c_handle_field_initializers_for(
    source_path: &Path,
    target_name: &str,
) -> Vec<MinedCFieldInitializer> {
    let Some(root) = project_root_of(source_path) else {
        return Vec::new();
    };
    let mut budget = MAX_FILES;
    let mut files = BTreeSet::new();
    let mut dirs = named_dirs_recursive(&root, FUZZ_DIRS);
    dirs.extend(recipe_dirs(&root));
    for dir in dirs {
        files.extend(source_files(
            &dir,
            &["c", "cc", "cpp", "cxx", "h", "hpp"],
            &mut budget,
        ));
    }
    files.extend(root_recipe_source_files(
        &root,
        &["c", "cc", "cpp", "cxx", "h", "hpp"],
        &mut budget,
    ));

    let mut values = BTreeMap::<String, BTreeSet<String>>::new();
    let target_family = c_input_endpoint_family(target_name);
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        if !recipe_text_is_visible(&text) {
            continue;
        }
        let clean = strip_c_comments(&text);
        for function in protocol_functions(&clean) {
            for call in protocol_calls(function.body).into_iter().filter(|call| {
                call.receiver_is_direct
                    && (call.name == target_name
                        || target_family.is_some()
                            && c_input_endpoint_family(&call.name) == target_family)
            }) {
                let Some(call_at) = function.body.find(&call.source_expression) else {
                    continue;
                };
                for initializer in
                    mine_receiver_field_initializers(&function.body[..call_at], &call.receiver)
                {
                    values
                        .entry(initializer.field)
                        .or_default()
                        .insert(initializer.value);
                }
            }
        }
    }
    values
        .into_iter()
        .filter_map(|(field, values)| {
            (values.len() == 1).then(|| MinedCFieldInitializer {
                field,
                value: values.into_iter().next().expect("one initializer value"),
            })
        })
        .collect()
}

fn c_input_endpoint_family(name: &str) -> Option<&str> {
    let (family, variant) = name.rsplit_once('_')?;
    [
        "memory", "file", "filename", "path", "stdio", "stream", "buffer", "bytes", "string", "fd",
    ]
    .contains(&variant.to_ascii_lowercase().as_str())
    .then_some(family)
}

fn mine_receiver_field_initializers(prefix: &str, receiver: &str) -> Vec<MinedCFieldInitializer> {
    let mut latest = BTreeMap::<String, String>::new();
    for statement in prefix.split(';') {
        let statement = statement.trim();
        let Some((left, right)) = statement.rsplit_once('=') else {
            continue;
        };
        let left = left.trim();
        if left.ends_with(['=', '!', '<', '>', '+', '-', '*', '/', '%', '&', '|', '^']) {
            continue;
        }
        let Some(field) = [format!("{receiver}."), format!("{receiver}->")]
            .into_iter()
            .find_map(|prefix| left.strip_prefix(&prefix))
        else {
            continue;
        };
        let field = field.trim();
        if field.is_empty()
            || !field
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            || !field
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        {
            continue;
        }
        let Some(value) = safe_protocol_constant(right) else {
            continue;
        };
        latest.insert(field.to_owned(), value);
    }
    latest
        .into_iter()
        .map(|(field, value)| MinedCFieldInitializer { field, value })
        .collect()
}

/// Recover a bounded pull-parser drain loop from project-maintained code. This
/// retains only a narrow topology: the selected call writes a named `&output`,
/// a public cleanup function consumes that same object, and a field is compared
/// with a public terminal constant inside a loop. All four facts must occur in
/// one function, preventing unrelated examples from being stitched together.
pub(crate) fn c_output_drain_protocol_for(
    source_path: &Path,
    target_name: &str,
) -> Option<MinedCOutputDrainProtocol> {
    let root = project_root_of(source_path)?;
    let mut budget = MAX_FILES;
    let mut files = BTreeSet::new();
    let mut dirs = named_dirs_recursive(&root, FUZZ_DIRS);
    dirs.extend(recipe_dirs(&root));
    for dir in dirs {
        files.extend(source_files(
            &dir,
            &["c", "cc", "cpp", "cxx", "h", "hpp"],
            &mut budget,
        ));
    }
    files.extend(root_recipe_source_files(
        &root,
        &["c", "cc", "cpp", "cxx", "h", "hpp"],
        &mut budget,
    ));

    let mut candidates = BTreeSet::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        if !recipe_text_is_visible(&text) {
            continue;
        }
        let clean = strip_c_comments(&text);
        for function in protocol_functions(&clean) {
            if !function.body.contains("while") && !function.body.contains("for") {
                continue;
            }
            let calls = protocol_calls(function.body);
            for target in calls
                .iter()
                .filter(|call| call.name == target_name && call.receiver_is_direct)
            {
                for (argument_index, argument) in target.arguments.iter().enumerate().skip(1) {
                    if !argument.trim().starts_with('&') {
                        continue;
                    }
                    let Some(output_name) = leading_expression_identifier(argument) else {
                        continue;
                    };
                    let Some(cleanup) = calls.iter().find(|call| {
                        call.name != target_name
                            && call.arguments.len() == 1
                            && call.arguments[0].trim().starts_with('&')
                            && leading_expression_identifier(&call.arguments[0]).as_deref()
                                == Some(output_name.as_str())
                            && ["delete", "destroy", "free", "clear", "release"]
                                .iter()
                                .any(|verb| call.name.to_ascii_lowercase().contains(verb))
                    }) else {
                        continue;
                    };
                    let Some((terminal_field, terminal_value)) =
                        receiver_terminal_comparison(function.body, &output_name)
                    else {
                        continue;
                    };
                    candidates.insert(MinedCOutputDrainProtocol {
                        output_argument: argument_index - 1,
                        cleanup_name: cleanup.name.clone(),
                        terminal_field,
                        terminal_value,
                    });
                }
            }
        }
    }
    (candidates.len() == 1).then(|| candidates.into_iter().next().expect("one drain protocol"))
}

fn receiver_terminal_comparison(body: &str, receiver: &str) -> Option<(String, String)> {
    let needle = format!("{receiver}.");
    let mut offset = 0usize;
    while let Some(relative) = body[offset..].find(&needle) {
        let start = offset + relative + needle.len();
        let field_len = body[start..]
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .count();
        if field_len == 0 {
            offset = start;
            continue;
        }
        let field = &body[start..start + field_len];
        let rest = body[start + field_len..].trim_start();
        let Some(rest) = rest.strip_prefix("==") else {
            offset = start + field_len;
            continue;
        };
        let value = rest
            .trim_start()
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect::<String>();
        if let Some(value) = safe_protocol_constant(&value) {
            return Some((field.to_owned(), value));
        }
        offset = start + field_len;
    }
    None
}

fn named_dirs_recursive(root: &Path, names: &[&str]) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(dir) = stack.pop() {
        visited += 1;
        if visited > 2_000 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name.starts_with('.') {
                continue;
            }
            if names.contains(&name.as_str()) {
                found.push(path);
            } else {
                stack.push(path);
            }
        }
    }
    found
}

/// Extract ordered calls and group them by the first argument's receiver.
/// This scanner is balanced-parenthesis aware, so multiline calls and nested
/// status reads survive (both are common in maintained fuzz harnesses).
pub(crate) fn mine_protocol_traces(text: &str) -> Vec<MinedProtocolTrace> {
    let clean = strip_c_comments(text);
    let functions = protocol_functions(&clean);
    let mut scopes = if functions.is_empty() {
        vec![protocol_calls(&clean)]
    } else {
        functions
            .iter()
            .map(|function| expand_protocol_function(function, &functions, &mut Vec::new(), 0))
            .collect()
    };
    let defines = protocol_constant_definitions(&clean);
    for calls in &mut scopes {
        fold_protocol_call_constants(calls, &defines);
    }
    let mut traces = Vec::new();
    for calls in scopes {
        let mut per_receiver: BTreeMap<String, MinedProtocolTrace> = BTreeMap::new();
        for call in calls {
            per_receiver
                .entry(call.receiver.clone())
                .or_default()
                .push(call);
        }
        traces.extend(per_receiver.into_values().filter(|trace| trace.len() >= 2));
    }
    traces
}

fn protocol_constant_definitions(text: &str) -> BTreeMap<String, String> {
    let mut definitions = BTreeMap::new();
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("define") else {
            continue;
        };
        let rest = rest.trim_start();
        let name_len = rest
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .count();
        if name_len == 0 || rest.as_bytes().get(name_len) == Some(&b'(') {
            continue;
        }
        let name = &rest[..name_len];
        let value = rest[name_len..].trim();
        if !value.is_empty() {
            definitions.insert(name.to_owned(), value.to_owned());
        }
    }
    definitions
}

fn fold_protocol_call_constants(
    calls: &mut [MinedProtocolCall],
    definitions: &BTreeMap<String, String>,
) {
    for call in calls {
        for argument in &mut call.arguments {
            if let Some(value) = fold_protocol_constant(argument, definitions, 0) {
                *argument = value;
            }
        }
        if let Some(condition) = &mut call.condition {
            if let Some(value) = fold_protocol_constant(&condition.value, definitions, 0) {
                condition.value = value;
            }
        }
    }
}

fn fold_protocol_constant(
    expression: &str,
    definitions: &BTreeMap<String, String>,
    depth: usize,
) -> Option<String> {
    if depth >= 8 {
        return None;
    }
    let expression = strip_balanced_outer_parens(expression.trim());
    if let Some(literal) = safe_protocol_literal(expression) {
        return Some(literal);
    }
    if expression
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return definitions
            .get(expression)
            .and_then(|value| fold_protocol_constant(value, definitions, depth + 1));
    }
    eval_protocol_integer(expression, definitions, depth).map(|value| value.to_string())
}

fn strip_balanced_outer_parens(mut expression: &str) -> &str {
    loop {
        if !expression.starts_with('(') {
            return expression;
        }
        let Some(close) = matching_paren(expression, 0) else {
            return expression;
        };
        if !expression[close + 1..].trim().is_empty() {
            return expression;
        }
        expression = expression[1..close].trim();
    }
}

fn eval_protocol_integer(
    expression: &str,
    definitions: &BTreeMap<String, String>,
    depth: usize,
) -> Option<i128> {
    if depth >= 16 {
        return None;
    }
    let expression = strip_balanced_outer_parens(expression.trim());
    for operators in [
        &["|"][..],
        &["^"][..],
        &["&"][..],
        &["<<", ">>"][..],
        &["+", "-"][..],
        &["*", "/", "%"][..],
    ] {
        if let Some((left, operator, right)) = split_protocol_binary(expression, operators) {
            let left = eval_protocol_integer(left, definitions, depth + 1)?;
            let right = eval_protocol_integer(right, definitions, depth + 1)?;
            return match operator {
                "|" => Some(left | right),
                "^" => Some(left ^ right),
                "&" => Some(left & right),
                "<<" => u32::try_from(right)
                    .ok()
                    .and_then(|shift| left.checked_shl(shift)),
                ">>" => u32::try_from(right)
                    .ok()
                    .and_then(|shift| left.checked_shr(shift)),
                "+" => left.checked_add(right),
                "-" => left.checked_sub(right),
                "*" => left.checked_mul(right),
                "/" => (right != 0)
                    .then_some(())
                    .and_then(|()| left.checked_div(right)),
                "%" => (right != 0)
                    .then_some(())
                    .and_then(|()| left.checked_rem(right)),
                _ => None,
            };
        }
    }
    if let Some(rest) = expression.strip_prefix('~') {
        return Some(!eval_protocol_integer(rest, definitions, depth + 1)?);
    }
    if let Some(rest) = expression.strip_prefix('+') {
        return eval_protocol_integer(rest, definitions, depth + 1);
    }
    if let Some(rest) = expression.strip_prefix('-') {
        return eval_protocol_integer(rest, definitions, depth + 1)?.checked_neg();
    }
    if expression
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        if let Some(value) = definitions.get(expression) {
            return eval_protocol_integer(value, definitions, depth + 1);
        }
    }
    parse_protocol_integer_literal(expression)
}

fn split_protocol_binary<'a, 'b>(
    expression: &'a str,
    operators: &'b [&'b str],
) -> Option<(&'a str, &'b str, &'a str)> {
    let bytes = expression.as_bytes();
    let mut depth = 0usize;
    let mut quote = None::<u8>;
    let mut escaped = false;
    let mut found = None;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.checked_sub(1)?,
            _ if depth == 0 => {
                for operator in operators {
                    if expression[index..].starts_with(operator) {
                        let doubled = (*operator == "|" && expression[index..].starts_with("||"))
                            || (*operator == "&" && expression[index..].starts_with("&&"));
                        if !doubled && !expression[..index].trim().is_empty() {
                            found = Some((index, *operator));
                        }
                        index += operator.len().saturating_sub(1);
                        break;
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
    let (at, operator) = found?;
    let right = expression[at + operator.len()..].trim();
    (!right.is_empty()).then_some((expression[..at].trim(), operator, right))
}

fn parse_protocol_integer_literal(expression: &str) -> Option<i128> {
    let value = expression.trim().trim_end_matches(['u', 'U', 'l', 'L']);
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        i128::from_str_radix(hex, 16).ok()
    } else if value.len() > 1
        && value.starts_with('0')
        && value.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
    {
        i128::from_str_radix(value, 8).ok()
    } else {
        value.parse().ok()
    }
}

#[derive(Debug, Clone)]
struct ProtocolFunction<'a> {
    name: String,
    params: Vec<String>,
    body: &'a str,
}

fn protocol_functions(text: &str) -> Vec<ProtocolFunction<'_>> {
    let mut functions = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'{' {
            index += 1;
            continue;
        }
        let brace = index;
        let Some(end) = matching_delimiter(text, brace, b'{', b'}') else {
            break;
        };
        let mut close = brace;
        while close > 0 && (bytes[close - 1] as char).is_ascii_whitespace() {
            close -= 1;
        }
        if close == 0 || bytes[close - 1] != b')' {
            index += 1;
            continue;
        }
        close -= 1;
        let Some(open) = matching_open_paren(text, close) else {
            index += 1;
            continue;
        };
        let before = text[..open].trim_end();
        let name_start = before
            .char_indices()
            .rev()
            .find(|(_, ch)| !ch.is_ascii_alphanumeric() && *ch != '_')
            .map_or(0, |(at, ch)| at + ch.len_utf8());
        let name = before[name_start..].trim();
        if name.is_empty()
            || matches!(name, "if" | "for" | "while" | "switch" | "catch")
            || !name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            index += 1;
            continue;
        }
        let params = split_arguments(&text[open + 1..close])
            .into_iter()
            .filter_map(protocol_parameter_name)
            .collect();
        functions.push(ProtocolFunction {
            name: name.to_owned(),
            params,
            body: &text[brace + 1..end],
        });
        index = end + 1;
    }
    functions
}

fn protocol_parameter_name(param: String) -> Option<String> {
    let param = param.trim();
    if param.is_empty() || param == "void" || param == "..." {
        return None;
    }
    let bytes = param.as_bytes();
    let mut end = bytes.len();
    while end > 0 && !(bytes[end - 1] as char).is_ascii_alphanumeric() && bytes[end - 1] != b'_' {
        end -= 1;
    }
    let mut start = end;
    while start > 0
        && ((bytes[start - 1] as char).is_ascii_alphanumeric() || bytes[start - 1] == b'_')
    {
        start -= 1;
    }
    (start < end).then(|| param[start..end].to_owned())
}

fn expand_protocol_function(
    function: &ProtocolFunction<'_>,
    functions: &[ProtocolFunction<'_>],
    stack: &mut Vec<String>,
    depth: usize,
) -> Vec<MinedProtocolCall> {
    if depth >= 4 || stack.contains(&function.name) {
        return protocol_calls(function.body);
    }
    stack.push(function.name.clone());
    let mut expanded = Vec::new();
    for call in protocol_calls(function.body) {
        let Some(helper) = functions.iter().find(|candidate| {
            candidate.name == call.name && candidate.params.len() == call.arguments.len()
        }) else {
            expanded.push(call);
            continue;
        };
        let substitutions = helper
            .params
            .iter()
            .zip(&call.arguments)
            .map(|(formal, actual)| (formal.as_str(), actual.as_str()))
            .collect::<Vec<_>>();
        for nested in expand_protocol_function(helper, functions, stack, depth + 1) {
            expanded.push(substitute_protocol_call(nested, &substitutions));
        }
    }
    stack.pop();
    expanded
}

fn substitute_protocol_call(
    mut call: MinedProtocolCall,
    substitutions: &[(&str, &str)],
) -> MinedProtocolCall {
    for (formal, actual) in substitutions {
        call.receiver = replace_protocol_identifier(&call.receiver, formal, actual);
        call.arguments = call
            .arguments
            .into_iter()
            .map(|arg| replace_protocol_identifier(&arg, formal, actual))
            .collect();
        call.source_expression =
            replace_protocol_identifier(&call.source_expression, formal, actual);
        if call.assigned_to.as_deref() == Some(*formal) {
            call.assigned_to = leading_expression_identifier(actual);
        }
        if let Some(condition) = &mut call.condition {
            condition.producer_receiver =
                replace_protocol_identifier(&condition.producer_receiver, formal, actual);
        }
        if let Some(condition) = &mut call.input_condition {
            match &mut condition.source {
                MinedProtocolInputSource::Size { input_name }
                | MinedProtocolInputSource::Byte { input_name, .. } => {
                    *input_name = replace_protocol_identifier(input_name, formal, actual);
                }
            }
        }
    }
    call.receiver = root_expression_identifier(&call.receiver).unwrap_or(call.receiver);
    call
}

fn replace_protocol_identifier(text: &str, identifier: &str, replacement: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len() + replacement.len());
    let mut index = 0usize;
    let mut quote = None::<u8>;
    let mut escaped = false;
    while index < bytes.len() {
        if let Some(active) = quote {
            let byte = bytes[index];
            out.push(byte as char);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            index += 1;
        } else if matches!(bytes[index], b'\'' | b'"') {
            quote = Some(bytes[index]);
            out.push(bytes[index] as char);
            index += 1;
        } else if (bytes[index] as char).is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && ((bytes[index] as char).is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            if &text[start..index] == identifier {
                out.push_str(replacement);
            } else {
                out.push_str(&text[start..index]);
            }
        } else {
            out.push(bytes[index] as char);
            index += 1;
        }
    }
    out
}

fn protocol_calls(text: &str) -> Vec<MinedProtocolCall> {
    let bytes = text.as_bytes();
    let mut out = Vec::<(usize, usize, MinedProtocolCall)>::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if !(bytes[index] as char).is_ascii_alphabetic() && bytes[index] != b'_' {
            index += 1;
            continue;
        }
        let name_start = index;
        index += 1;
        while index < bytes.len()
            && ((bytes[index] as char).is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        let name = &text[name_start..index];
        let mut open = index;
        while open < bytes.len() && (bytes[open] as char).is_ascii_whitespace() {
            open += 1;
        }
        if open >= bytes.len()
            || bytes[open] != b'('
            || matches!(
                name,
                "if" | "for" | "while" | "switch" | "return" | "sizeof" | "assert"
            )
        {
            continue;
        }
        let Some(close) = matching_paren(text, open) else {
            continue;
        };
        let arguments = split_arguments(&text[open + 1..close])
            .into_iter()
            .map(|arg| arg.trim().to_owned())
            .collect::<Vec<_>>();
        let direct_receiver = arguments
            .first()
            .and_then(|arg| leading_expression_identifier(arg));
        let receiver = arguments
            .first()
            .and_then(|arg| root_expression_identifier(arg));
        if let Some(receiver) = receiver {
            out.push((
                close,
                name_start,
                MinedProtocolCall {
                    name: name.to_owned(),
                    receiver_is_direct: direct_receiver.as_deref() == Some(receiver.as_str()),
                    receiver,
                    arguments,
                    assigned_to: assigned_identifier(text, name_start),
                    source_expression: text[name_start..=close].trim().to_owned(),
                    condition: enclosing_protocol_condition(text, name_start),
                    input_condition: enclosing_protocol_input_condition(text, name_start),
                },
            ));
        }
        // Advance only beyond the opening parenthesis, not the whole call: a
        // nested `ErrorString(GetErrorCode(parser))` must retain the inner call.
        index = open + 1;
    }
    // A nested call completes before its enclosing call. Ordering by closing
    // parenthesis preserves that evaluation dependency while retaining lexical
    // order for ordinary sequential calls.
    out.sort_by_key(|(close, start, _)| (*close, *start));
    out.into_iter().map(|(_, _, call)| call).collect()
}

/// Recover the common expert-harness shape
/// `if (parse(handle, ...) == STATUS_ERROR) { inspect(handle); }` without
/// attempting to lift arbitrary control flow. Braces, a direct call comparison,
/// and a self-contained literal or macro-like constant are all required.
fn enclosing_protocol_condition(text: &str, call_start: usize) -> Option<MinedProtocolCondition> {
    let (expression, inverted) = enclosing_protocol_if_branch(text, call_start)?;
    let mut condition = protocol_predicate_atoms(expression)
        .into_iter()
        .find_map(parse_protocol_condition)?;
    if inverted {
        condition.comparison = negate_protocol_comparison(condition.comparison);
    }
    Some(condition)
}

fn enclosing_protocol_input_condition(
    text: &str,
    call_start: usize,
) -> Option<MinedProtocolInputCondition> {
    let (expression, inverted) = enclosing_protocol_if_branch(text, call_start)?;
    let mut condition = protocol_predicate_atoms(expression)
        .into_iter()
        .filter_map(parse_protocol_input_condition)
        // A byte predicate carries its own bounds check during emission and is
        // more semantically discriminating than the accompanying `size > N`.
        .max_by_key(|condition| {
            usize::from(matches!(
                condition.source,
                MinedProtocolInputSource::Byte { .. }
            ))
        })?;
    if inverted {
        condition.comparison = negate_protocol_comparison(condition.comparison);
    }
    Some(condition)
}

fn protocol_predicate_atoms(expression: &str) -> Vec<&str> {
    fn collect<'a>(expression: &'a str, out: &mut Vec<&'a str>) {
        let expression = strip_balanced_outer_parens(expression.trim());
        if let Some((left, _, right)) = split_protocol_binary(expression, &["&&"]) {
            collect(left, out);
            collect(right, out);
        } else {
            out.push(expression);
        }
    }
    let mut out = Vec::new();
    collect(expression, &mut out);
    out
}

/// Return the closest enclosing `if` predicate and whether the call is in its
/// direct `else` branch. This is a deliberately small control-flow slice: it
/// preserves the common two-way expert protocol without attempting to model an
/// arbitrary CFG. Negating the comparison makes calls from the two arms
/// mutually exclusive when codegen replays the otherwise lexical call list.
fn enclosing_protocol_if_branch(text: &str, call_start: usize) -> Option<(&str, bool)> {
    let mut search = call_start;
    while let Some(open_brace) = text[..search].rfind('{') {
        let close_brace = matching_delimiter(text, open_brace, b'{', b'}')?;
        if close_brace < call_start {
            search = open_brace;
            continue;
        }

        if let Some(expression) = protocol_if_expression_before_brace(text, open_brace) {
            return Some((expression, false));
        }
        if let Some(expression) = protocol_else_expression_before_brace(text, open_brace) {
            return Some((expression, true));
        }
        search = open_brace;
    }
    None
}

fn protocol_if_expression_before_brace(text: &str, open_brace: usize) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut close_paren = open_brace;
    while close_paren > 0 && (bytes[close_paren - 1] as char).is_ascii_whitespace() {
        close_paren -= 1;
    }
    if close_paren == 0 || bytes[close_paren - 1] != b')' {
        return None;
    }
    close_paren -= 1;
    let open_paren = matching_open_paren(text, close_paren)?;
    let keyword = text[..open_paren]
        .trim_end()
        .rsplit_once(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .map_or_else(|| text[..open_paren].trim(), |(_, tail)| tail);
    (keyword == "if").then(|| text[open_paren + 1..close_paren].trim())
}

fn protocol_else_expression_before_brace(text: &str, open_brace: usize) -> Option<&str> {
    let before_else = text[..open_brace].trim_end().strip_suffix("else")?;
    if before_else
        .chars()
        .next_back()
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    let close_if = before_else.trim_end().len().checked_sub(1)?;
    if text.as_bytes().get(close_if) != Some(&b'}') {
        return None;
    }

    let mut search = close_if;
    while let Some(open_if) = text[..search].rfind('{') {
        if matching_delimiter(text, open_if, b'{', b'}') == Some(close_if) {
            return protocol_if_expression_before_brace(text, open_if);
        }
        search = open_if;
    }
    None
}

fn parse_protocol_input_condition(expression: &str) -> Option<MinedProtocolInputCondition> {
    let expression = strip_balanced_outer_parens(expression.trim());
    let (operand, comparison, value) =
        if let Some((left, comparison, right)) = split_top_level_comparison(expression) {
            (left, comparison, safe_protocol_constant(right)?)
        } else {
            (
                expression,
                MinedProtocolComparison::NotEqual,
                "0".to_owned(),
            )
        };
    let (source, transform) = parse_protocol_input_operand(operand)?;
    if value.trim_start().starts_with('-') {
        return None;
    }
    if let MinedProtocolInputTransform::Modulo(modulus) = transform {
        if let Some(remainder) =
            parse_protocol_integer_literal(&value).and_then(|parsed| u64::try_from(parsed).ok())
        {
            if remainder >= modulus {
                return None;
            }
        }
    }
    Some(MinedProtocolInputCondition {
        source,
        transform,
        comparison,
        value,
    })
}

fn parse_protocol_input_operand(
    expression: &str,
) -> Option<(MinedProtocolInputSource, MinedProtocolInputTransform)> {
    let expression = strip_balanced_outer_parens(expression.trim());
    let (base, transform) =
        if let Some((left, _, right)) = split_protocol_binary(expression, &["%"]) {
            let modulus = parse_protocol_integer_literal(right)
                .and_then(|value| u64::try_from(value).ok())?;
            if modulus == 0 || modulus > 65_536 {
                return None;
            }
            (left, MinedProtocolInputTransform::Modulo(modulus))
        } else if let Some((left, _, right)) = split_protocol_binary(expression, &["&"]) {
            let mask = parse_protocol_integer_literal(right)
                .and_then(|value| u64::try_from(value).ok())?;
            (left, MinedProtocolInputTransform::BitAnd(mask))
        } else {
            (expression, MinedProtocolInputTransform::Identity)
        };
    let base = strip_balanced_outer_parens(base.trim());
    if ["size", "len", "length", "nbytes", "data_len", "input_size"]
        .iter()
        .any(|name| base.eq_ignore_ascii_case(name))
    {
        return Some((
            MinedProtocolInputSource::Size {
                input_name: base.to_owned(),
            },
            transform,
        ));
    }
    let open = base.find('[')?;
    let close = base.rfind(']')?;
    if close + 1 != base.len() {
        return None;
    }
    let input_name = base[..open].trim();
    if !["data", "input", "bytes", "buffer", "buf", "src", "source"]
        .iter()
        .any(|name| input_name.eq_ignore_ascii_case(name))
    {
        return None;
    }
    let index = base[open + 1..close].trim().parse::<usize>().ok()?;
    if index > 4096 {
        return None;
    }
    Some((
        MinedProtocolInputSource::Byte {
            input_name: input_name.to_owned(),
            index,
        },
        transform,
    ))
}

fn parse_protocol_condition(expression: &str) -> Option<MinedProtocolCondition> {
    let (left, comparison, right) = split_top_level_comparison(expression)?;
    let (call, bitmask, comparison, value) =
        if let Some((call, bitmask)) = parse_protocol_result_operand(left) {
            (call, bitmask, comparison, right)
        } else {
            let (call, bitmask) = parse_protocol_result_operand(right)?;
            (call, bitmask, reverse_protocol_comparison(comparison), left)
        };
    let value = safe_protocol_constant(value)?;
    Some(MinedProtocolCondition {
        producer_name: call.name,
        producer_receiver: call.receiver,
        bitmask,
        comparison,
        value,
    })
}

fn parse_protocol_result_operand(expression: &str) -> Option<(MinedProtocolCall, Option<String>)> {
    let expression = strip_balanced_outer_parens(expression.trim());
    if let Some(call) = parse_complete_protocol_call(expression) {
        return Some((call, None));
    }
    let (left, _, right) = split_protocol_binary(expression, &["&"])?;
    let call = parse_complete_protocol_call(strip_balanced_outer_parens(left.trim()))?;
    Some((call, Some(safe_protocol_constant(right)?)))
}

fn reverse_protocol_comparison(comparison: MinedProtocolComparison) -> MinedProtocolComparison {
    match comparison {
        MinedProtocolComparison::Equal => MinedProtocolComparison::Equal,
        MinedProtocolComparison::NotEqual => MinedProtocolComparison::NotEqual,
        MinedProtocolComparison::Less => MinedProtocolComparison::Greater,
        MinedProtocolComparison::LessEqual => MinedProtocolComparison::GreaterEqual,
        MinedProtocolComparison::Greater => MinedProtocolComparison::Less,
        MinedProtocolComparison::GreaterEqual => MinedProtocolComparison::LessEqual,
    }
}

fn negate_protocol_comparison(comparison: MinedProtocolComparison) -> MinedProtocolComparison {
    match comparison {
        MinedProtocolComparison::Equal => MinedProtocolComparison::NotEqual,
        MinedProtocolComparison::NotEqual => MinedProtocolComparison::Equal,
        MinedProtocolComparison::Less => MinedProtocolComparison::GreaterEqual,
        MinedProtocolComparison::LessEqual => MinedProtocolComparison::Greater,
        MinedProtocolComparison::Greater => MinedProtocolComparison::LessEqual,
        MinedProtocolComparison::GreaterEqual => MinedProtocolComparison::Less,
    }
}

fn split_top_level_comparison(expression: &str) -> Option<(&str, MinedProtocolComparison, &str)> {
    let bytes = expression.as_bytes();
    let mut depth = 0usize;
    let mut quote = None::<u8>;
    let mut escaped = false;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.checked_sub(1)?,
            b'=' | b'!' | b'<' | b'>' if depth == 0 => {
                let (comparison, width) = match (byte, bytes.get(index + 1).copied()) {
                    (b'=', Some(b'=')) => (MinedProtocolComparison::Equal, 2),
                    (b'!', Some(b'=')) => (MinedProtocolComparison::NotEqual, 2),
                    (b'<', Some(b'=')) => (MinedProtocolComparison::LessEqual, 2),
                    (b'>', Some(b'=')) => (MinedProtocolComparison::GreaterEqual, 2),
                    (b'<', _) => (MinedProtocolComparison::Less, 1),
                    (b'>', _) => (MinedProtocolComparison::Greater, 1),
                    _ => {
                        index += 1;
                        continue;
                    }
                };
                return Some((
                    expression[..index].trim(),
                    comparison,
                    expression[index + width..].trim(),
                ));
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn parse_complete_protocol_call(expression: &str) -> Option<MinedProtocolCall> {
    let expression = expression.trim();
    let open = expression.find('(')?;
    let close = matching_paren(expression, open)?;
    if !expression[close + 1..].trim().is_empty() {
        return None;
    }
    let name = expression[..open].trim();
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    let arguments = split_arguments(&expression[open + 1..close])
        .into_iter()
        .map(|arg| arg.trim().to_owned())
        .collect::<Vec<_>>();
    let receiver = arguments
        .first()
        .and_then(|arg| leading_expression_identifier(arg))?;
    Some(MinedProtocolCall {
        name: name.to_owned(),
        receiver_is_direct: true,
        receiver,
        arguments,
        assigned_to: None,
        source_expression: expression.to_owned(),
        condition: None,
        input_condition: None,
    })
}

fn matching_open_paren(text: &str, close: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut quote = None::<u8>;
    let mut escaped = false;
    for index in (0..=close).rev() {
        let byte = bytes[index];
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b')' => depth += 1,
            b'(' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn matching_delimiter(text: &str, open: usize, opening: u8, closing: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut quote = None::<u8>;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate().skip(open) {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            _ if byte == opening => depth += 1,
            _ if byte == closing => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn assigned_identifier(text: &str, call_start: usize) -> Option<String> {
    let prefix = text[..call_start].trim_end();
    let before_equals = prefix.strip_suffix('=')?.trim_end();
    // Comparisons and compound assignments are not object construction.
    if before_equals.ends_with(['=', '!', '<', '>', '+', '-', '*', '/', '%', '&', '|', '^']) {
        return None;
    }
    let start = before_equals
        .char_indices()
        .rev()
        .find(|(_, ch)| !ch.is_ascii_alphanumeric() && *ch != '_')
        .map_or(0, |(index, ch)| index + ch.len_utf8());
    let identifier = before_equals[start..].trim();
    (!identifier.is_empty()
        && identifier
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && identifier
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_'))
    .then(|| identifier.to_owned())
}

/// Constructor calls assigned to named objects in maintained fuzz targets.
/// These are used to reproduce the object topology an expert selected (for
/// example a base parser, a namespace parser, and children derived from the
/// base). Only the caller later decides whether a call really returns the
/// lifecycle handle type; the miner supplies evidence, not type authority.
pub(crate) fn protocol_constructions_for(source_path: &Path) -> Vec<MinedProtocolCall> {
    let Some(root) = project_root_of(source_path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut budget = MAX_FILES;
    for dir in named_dirs_recursive(&root, FUZZ_DIRS) {
        for file in source_files(&dir, &["c", "cc", "cpp", "cxx", "h", "hpp"], &mut budget) {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            if !recipe_text_is_visible(&text) {
                continue;
            }
            // A directory named `fuzz` can also contain support libraries. Keep
            // object-topology evidence to an actual maintained fuzz entrypoint.
            if !text.contains("LLVMFuzzerTestOneInput") && !text.contains("fuzz_target!") {
                continue;
            }
            let clean = strip_c_comments(&text);
            let mut calls = protocol_calls(&clean);
            fold_protocol_call_constants(&mut calls, &protocol_constant_definitions(&clean));
            for call in &calls {
                let Some(object) = call.assigned_to.as_deref() else {
                    continue;
                };
                // Construction alone is not evidence that the selected target
                // is legal on the object. Require the maintained fuzzer to pass
                // that exact variable to a non-destructor helper/API afterward.
                // Expat's `ParseOneInput(namespaceParser, ...)` and equivalent
                // wrappers satisfy this; a temporary allocated only to be freed
                // does not become a made-up protocol variant.
                let driven = calls.iter().any(|later| {
                    later.receiver == object
                        && later.assigned_to.is_none()
                        && !["free", "destroy", "delete", "release", "dispose"]
                            .iter()
                            .any(|verb| later.name.to_ascii_lowercase().contains(verb))
                });
                if driven && !out.contains(call) {
                    out.push(call.clone());
                }
            }
        }
    }
    out
}

/// Public state-changing APIs invoked by callbacks registered in maintained
/// fuzz entrypoints. The caller still validates receiver/parameter types and
/// lifecycle role. This only supplies behavioral evidence: e.g. Expat's
/// `may_stop_character_handler` calls `XML_StopParser`, proving that stop is a
/// legal callback-time action rather than speculative API misuse.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MinedCallbackAction {
    pub(crate) action_name: String,
    pub(crate) configuration_name: String,
    /// Index after the lifecycle receiver in the configuration declaration.
    pub(crate) configuration_arg: usize,
}

pub(crate) fn callback_actions_for(source_path: &Path) -> Vec<MinedCallbackAction> {
    let Some(root) = project_root_of(source_path) else {
        return Vec::new();
    };
    let mut actions = BTreeSet::new();
    let mut budget = MAX_FILES;
    let mut files = Vec::new();
    for dir in named_dirs_recursive(&root, FUZZ_DIRS) {
        files.extend(source_files(
            &dir,
            &["c", "cc", "cpp", "cxx", "h", "hpp"],
            &mut budget,
        ));
    }
    files.extend(root_recipe_source_files(
        &root,
        &["c", "cc", "cpp", "cxx", "h", "hpp"],
        &mut budget,
    ));
    files.sort();
    files.dedup();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        if !recipe_text_is_visible(&text) {
            continue;
        }
        if !text.contains("LLVMFuzzerTestOneInput") && !text.contains("fuzz_target!") {
            continue;
        }
        let clean = strip_c_comments(&text);
        let registered = protocol_calls(&clean)
            .into_iter()
            .filter(|call| {
                let lower = call.name.to_ascii_lowercase();
                lower.contains("handler") || lower.contains("callback")
            })
            .flat_map(|call| {
                let configuration_name = call.name;
                call.arguments.into_iter().skip(1).enumerate().filter_map(
                    move |(configuration_arg, arg)| {
                        leading_expression_identifier(&arg).map(|callback| {
                            (configuration_name.clone(), configuration_arg, callback)
                        })
                    },
                )
            })
            .collect::<BTreeSet<_>>();
        for (configuration_name, configuration_arg, callback) in registered {
            let Some(body) = function_body_for(&clean, &callback) else {
                continue;
            };
            for call in protocol_calls(body) {
                let lower = call.name.to_ascii_lowercase();
                if ["stop", "suspend", "resume", "abort", "cancel", "interrupt"]
                    .iter()
                    .any(|verb| lower.contains(verb))
                {
                    actions.insert(MinedCallbackAction {
                        action_name: call.name,
                        configuration_name: configuration_name.clone(),
                        configuration_arg,
                    });
                }
            }
        }
    }
    actions.into_iter().collect()
}

fn function_body_for<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let mut offset = 0usize;
    while let Some(relative) = text[offset..].find(name) {
        let start = offset + relative;
        let before = text[..start].chars().next_back();
        let after = text[start + name.len()..].chars().next();
        if before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            || after.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            offset = start + name.len();
            continue;
        }
        let mut open = start + name.len();
        while text
            .as_bytes()
            .get(open)
            .is_some_and(|byte| (*byte as char).is_ascii_whitespace())
        {
            open += 1;
        }
        if text.as_bytes().get(open) != Some(&b'(') {
            offset = start + name.len();
            continue;
        }
        let close = matching_paren(text, open)?;
        let mut brace = close + 1;
        while text
            .as_bytes()
            .get(brace)
            .is_some_and(|byte| (*byte as char).is_ascii_whitespace())
        {
            brace += 1;
        }
        if text.as_bytes().get(brace) != Some(&b'{') {
            offset = start + name.len();
            continue;
        }
        let end = matching_delimiter(text, brace, b'{', b'}')?;
        return Some(&text[brace + 1..end]);
    }
    None
}

fn matching_paren(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut quote = None::<u8>;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate().skip(open) {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' => depth += 1,
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn leading_expression_identifier(expr: &str) -> Option<String> {
    let mut text = expr.trim().trim_start_matches(['&', '*']).trim();
    // Peel ordinary C casts. This intentionally accepts only a balanced leading
    // parenthesis and then continues at the expression; a nested function call
    // remains its function name and therefore cannot masquerade as a handle.
    while text.starts_with('(') {
        let close = matching_paren(text, 0)?;
        let inside = text[1..close].trim();
        if inside.contains(',') || inside.contains('(') || inside.contains(')') {
            break;
        }
        text = text[close + 1..]
            .trim()
            .trim_start_matches(['&', '*'])
            .trim();
    }
    let identifier: String = text
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!identifier.is_empty()
        && !identifier
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit()))
    .then_some(identifier)
}

fn root_expression_identifier(expr: &str) -> Option<String> {
    let text = expr.trim().trim_start_matches(['&', '*']).trim();
    let name: String = text
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect();
    if !name.is_empty() {
        let rest = text[name.len()..].trim_start();
        if rest.starts_with('(') {
            let open = text.len() - rest.len();
            if let Some(close) = matching_paren(text, open) {
                if text[close + 1..].trim().is_empty() {
                    let first = split_arguments(&text[open + 1..close]).into_iter().next()?;
                    return root_expression_identifier(&first);
                }
            }
        }
    }
    leading_expression_identifier(expr)
}

/// Return a source spelling only when it is a self-contained C literal safe to
/// lift into another translation unit. Macro names, locals, helper calls and
/// compound expressions are intentionally rejected.
pub(crate) fn safe_protocol_literal(expr: &str) -> Option<String> {
    let value = expr.trim();
    is_literal(value).then(|| value.to_owned())
}

/// A comparison constant that can safely cross translation units. In addition
/// to ordinary literals, admit conventional public enum/macro spellings. The
/// deliberately strict uppercase grammar excludes locals, fields and helper
/// calls while covering constants such as `XML_STATUS_ERROR`, `Z_STREAM_END`,
/// and `ARCHIVE_EOF` supplied by the target's public header.
pub(crate) fn safe_protocol_constant(expr: &str) -> Option<String> {
    if let Some(literal) = safe_protocol_literal(expr) {
        return Some(literal);
    }
    let value = expr.trim();
    (value.contains('_')
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_uppercase() || ch == '_')
        && value
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_'))
    .then(|| value.to_owned())
}

fn strip_c_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0usize;
    let mut quote = None::<u8>;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(active) = quote {
            out.push(byte as char);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
            out.push(byte as char);
            index += 1;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                out.push(' ');
                index += 1;
            }
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            out.push(' ');
            out.push(' ');
            index += 2;
            while index < bytes.len() {
                if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    break;
                }
                out.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            continue;
        }
        out.push(byte as char);
        index += 1;
    }
    out
}

/// Mined call order for the project owning `source_path`, cached per project
/// like [`for_source`].
pub(crate) fn call_order_for(source_path: &Path) -> CallOrder {
    let Some(root) = project_root_of(source_path) else {
        return CallOrder::new();
    };
    let mut order = CallOrder::new();
    let mut budget = MAX_FILES;
    for dir in recipe_dirs(&root) {
        for file in source_files(&dir, &["c", "cc", "cpp", "cxx", "h", "hpp"], &mut budget) {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            if !recipe_text_is_visible(&text) {
                continue;
            }
            for (pair, count) in mine_call_order(&text) {
                *order.entry(pair).or_insert(0) += count;
            }
        }
    }
    for file in root_recipe_source_files(&root, &["c", "cc", "cpp", "cxx", "h", "hpp"], &mut budget)
    {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        if !recipe_text_is_visible(&text) {
            continue;
        }
        for (pair, count) in mine_call_order(&text) {
            *order.entry(pair).or_insert(0) += count;
        }
    }
    order
}

/// Whether the mined evidence says `earlier` is called before `later` more often
/// than the reverse. `None` when the pair was never observed in either order.
pub(crate) fn precedes(order: &CallOrder, earlier: &str, later: &str) -> Option<bool> {
    let forward = order
        .get(&(earlier.to_owned(), later.to_owned()))
        .copied()
        .unwrap_or(0);
    let backward = order
        .get(&(later.to_owned(), earlier.to_owned()))
        .copied()
        .unwrap_or(0);
    (forward + backward > 0).then_some(forward > backward)
}

/// Directories that hold test DATA rather than test code: the real `.tar`,
/// `.zip`, `.xml` and `.gz` inputs a project keeps for its own suite.
const SEED_DIRS: &[&str] = &[
    "testdata",
    "test_data",
    "fixtures",
    "corpus",
    "corpora",
    "seeds",
    "samples",
    "data",
    "inputs",
    "files",
];

/// Extensions that are SOURCE, not data. A `.c` file is not a seed — feeding
/// the fuzzer its own target's source wastes budget on inputs the parser was
/// never going to accept.
const NON_SEED_EXTENSIONS: &[&str] = &[
    "c", "h", "cc", "cpp", "cxx", "hpp", "hxx", "rs", "py", "pl", "rb", "go", "java", "cs", "js",
    "ts", "lua", "php", "ads", "adb", "gpr", "md", "txt", "toml", "yaml", "yml", "json", "cmake",
    "am", "ac", "in", "sh", "bat", "mk", "o", "a", "so", "exe",
];

/// Largest seed to lift out of a tree, and how many. A seed corpus is a
/// nice-to-have; it must never turn discovery into a whole-repository copy.
const MAX_SEED_BYTES: u64 = 256 * 1024;
const MAX_SEEDS: usize = 64;

/// Benchmark isolation switch: when set, maintained fuzz entrypoints remain
/// available to the expert oracle but are excluded from every recipe miner.
/// This prevents an auto-vs-expert experiment from grading a generated harness
/// that directly learned from the answer key. Ordinary tests/examples and seed
/// data remain visible, matching what govfuzz can use on a project with no
/// hand-written fuzzer.
fn recipe_text_is_visible(text: &str) -> bool {
    std::env::var_os("GOVFUZZ_BLIND_EXPERT_HARNESSES").is_none()
        || (!text.contains("LLVMFuzzerTestOneInput") && !text.contains("fuzz_target!"))
}

/// Return true when maintained examples/tests prove that a lifecycle
/// initializer uses boolean (nonzero) success. C has no type-level distinction
/// between a bool-like `int` and an errno-like status `int`; blindly assuming
/// zero success suppresses every operation for APIs such as libyaml.
pub(crate) fn initializer_success_is_nonzero(source_path: &Path, name: &str) -> bool {
    let Some(root) = project_root_of(source_path) else {
        return false;
    };
    let escaped = regex::escape(name);
    let patterns = [
        format!(r"assert\s*\(\s*{escaped}\s*\("),
        format!(r"if\s*\(\s*!\s*{escaped}\s*\("),
    ];
    let patterns = patterns
        .iter()
        .filter_map(|pattern| regex::Regex::new(pattern).ok())
        .collect::<Vec<_>>();
    let mut budget = MAX_FILES;
    let mut files = recipe_dirs(&root)
        .into_iter()
        .flat_map(|dir| source_files(&dir, &["c", "h", "cc", "cpp", "cxx"], &mut budget))
        .collect::<Vec<_>>();
    files.extend(root_recipe_source_files(
        &root,
        &["c", "h", "cc", "cpp", "cxx"],
        &mut budget,
    ));
    // Private helpers are often used only inside the implementation target
    // itself (libpng's png_image_read_init). Their surrounding comparison is
    // still authoritative API semantics, not an expert harness answer key.
    files.push(source_path.to_path_buf());
    files.into_iter().any(|path| {
        std::fs::read_to_string(path)
            .ok()
            .filter(|text| recipe_text_is_visible(text))
            .is_some_and(|text| patterns.iter().any(|pattern| pattern.is_match(&text)))
    })
}

/// Harvest a seed corpus from the project's own test-data directories.
///
/// Expert harness quality is not all in the harness: a parser reached through
/// random bytes spends its budget bouncing off the header check, while the same
/// harness given one real `.tar` starts inside the format. Projects already ship
/// those files — libarchive, libexpat and zlib all keep real inputs beside their
/// tests — and govfuzz walked straight past them, seeding only from `--seed-dir`.
pub(crate) fn mine_seed_corpus(root: &Path) -> Vec<std::path::PathBuf> {
    let mut seeds = Vec::new();
    let mut budget = MAX_FILES;
    for dir in recipe_dirs(root) {
        collect_seed_files(&dir, &mut seeds, &mut budget);
    }
    seeds.sort();
    seeds.truncate(MAX_SEEDS);
    seeds
}

fn collect_seed_files(dir: &Path, out: &mut Vec<std::path::PathBuf>, budget: &mut usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *budget == 0 || out.len() >= MAX_SEEDS {
            return;
        }
        let path = entry.path();
        if path.is_dir() {
            let named_data = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| SEED_DIRS.contains(&n.to_ascii_lowercase().as_str()))
                .unwrap_or(false);
            if named_data {
                collect_seed_files(&path, out, budget);
            }
            continue;
        }
        *budget -= 1;
        if !is_seed_candidate(&path) {
            continue;
        }
        out.push(path);
    }
}

fn is_seed_candidate(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_SEED_BYTES {
        return false;
    }
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    // An extensionless file in a data directory is usually a fixture; a known
    // SOURCE extension never is.
    !NON_SEED_EXTENSIONS.contains(&extension.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_direct_initialization_with_literals_is_mined() {
        let mined = mine_text("  Widget w(3, \"name\");\n");
        assert_eq!(
            mined.get("Widget").map(String::as_str),
            Some("Widget(3, \"name\")")
        );
    }

    #[test]
    fn a_named_factory_assignment_is_mined_verbatim() {
        let mined = mine_text("Parser p = Parser::of(7);");
        assert_eq!(
            mined.get("Parser").map(String::as_str),
            Some("Parser::of(7)")
        );
    }

    #[test]
    fn a_construction_naming_a_local_variable_is_refused() {
        // This is the property that makes mining safe: the expression has to
        // survive being lifted out of the test it was written in.
        assert!(mine_text("Widget w(fixture_size);").is_empty());
        assert!(mine_text("Parser p = Parser::of(cfg);").is_empty());
    }

    #[test]
    fn a_default_construction_is_mined() {
        let mined = mine_text("Widget w();");
        assert_eq!(mined.get("Widget").map(String::as_str), Some("Widget()"));
    }

    #[test]
    fn a_primitive_declaration_yields_no_recipe() {
        // Nothing needs a recipe to build an int, and mining one would only add
        // noise to the registry.
        assert!(mine_text("int x(3);").is_empty());
        assert!(mine_text("size_t n(0);").is_empty());
    }

    #[test]
    fn a_pointer_declaration_is_not_a_value_construction() {
        assert!(mine_text("Widget* w(nullptr);").is_empty());
    }

    #[test]
    fn a_comment_is_not_mined() {
        assert!(mine_text("// Widget w(3);").is_empty());
        assert!(mine_text(" * Widget w(3);").is_empty());
    }

    #[test]
    fn the_shortest_construction_wins() {
        // Fewer arguments is less to be wrong about, and likelier to stay
        // literal-only.
        let mined = mine_text(
            "Widget a(1, 2, 3, \"long\");\n\
             Widget b(1);\n",
        );
        assert_eq!(mined.get("Widget").map(String::as_str), Some("Widget(1)"));
    }

    #[test]
    fn a_nested_call_argument_is_not_a_literal() {
        assert!(mine_text("Widget w(make_size(3));").is_empty());
    }

    #[test]
    fn a_qualified_class_name_is_kept_whole() {
        let mined = mine_text("ns::Widget w(1);");
        assert_eq!(
            mined.get("ns::Widget").map(String::as_str),
            Some("ns::Widget(1)")
        );
    }

    #[test]
    fn const_and_static_noise_does_not_prevent_mining() {
        let mined = mine_text("const Widget w(2);");
        assert_eq!(mined.get("Widget").map(String::as_str), Some("Widget(2)"));
    }

    #[test]
    fn a_bare_expression_statement_is_not_a_recipe() {
        // `Widget(3);` constructs a temporary and discards it; it names no
        // object, so there is nothing to learn about declaring one.
        assert!(mine_text("Widget(3);").is_empty());
    }

    #[test]
    fn mining_a_tree_reads_only_the_example_directories() {
        let root = std::env::temp_dir().join(format!("govfuzz-mine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("tests")).unwrap();
        std::fs::write(root.join("src/lib.cpp"), "Widget shipped(9);").unwrap();
        std::fs::write(root.join("tests/t.cpp"), "Widget w(4);").unwrap();

        let mined = mine(&root, &["cpp"]);

        assert_eq!(
            mined.get("Widget").map(String::as_str),
            Some("Widget(4)"),
            "the recipe must come from the test tree"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn call_order_is_mined_from_the_shape_zlibs_own_test_uses() {
        // zlib's test/example.c drives the stream `deflateInit` -> `deflate` ->
        // `deflateEnd` on one `z_stream`. That order IS the contract, and nothing
        // in a declaration states it — ops were previously ordered by declaration
        // line, which is arbitrary with respect to the API.
        let text = r#"
            int test_flush(Byte *compr, uLong *comprLen) {
                z_stream c_stream;
                err = deflateInit(&c_stream, Z_DEFAULT_COMPRESSION);
                err = deflate(&c_stream, Z_FULL_FLUSH);
                err = deflate(&c_stream, Z_FINISH);
                err = deflateEnd(&c_stream);
            }
        "#;
        let order = mine_call_order(text);
        assert_eq!(precedes(&order, "deflateInit", "deflate"), Some(true));
        assert_eq!(precedes(&order, "deflate", "deflateEnd"), Some(true));
        // ...and the reverse reads as false rather than as "no evidence".
        assert_eq!(precedes(&order, "deflateEnd", "deflateInit"), Some(false));
        // A pair never seen together has no opinion, which must not be confused
        // with an ordering claim.
        assert_eq!(precedes(&order, "deflateInit", "inflateEnd"), None);
    }

    #[test]
    fn calls_on_different_objects_are_not_ordered_against_each_other() {
        // The shared first argument is what makes this evidence about ONE
        // object's lifecycle. Two unrelated calls that happen to be adjacent
        // must not manufacture a contract.
        let text = "open_a(&left); close_b(&right);";
        let order = mine_call_order(text);
        assert_eq!(precedes(&order, "open_a", "close_b"), None);
    }

    #[test]
    fn control_keywords_are_not_mistaken_for_calls() {
        let text = "if (thing) { use(thing); } while (thing) { step(thing); }";
        let order = mine_call_order(text);
        assert_eq!(precedes(&order, "use", "step"), Some(true));
        assert_eq!(precedes(&order, "if", "use"), None);
        assert_eq!(precedes(&order, "while", "step"), None);
    }

    #[test]
    fn expert_streaming_protocol_preserves_repetition_literals_and_status_reads() {
        // This is the essential shape of Expat's maintained OSS-Fuzz helper.
        // The two parse calls are semantically different: the first streams a
        // chunk, the second finalizes the document. Flattening them to one
        // randomly-parameterized operation loses the finalization paths.
        let text = r#"
            static void ParseOneInput(XML_Parser p,
                                      const uint8_t *data, size_t size) {
                XML_Parse(p, (const XML_Char *)data, (int)size, 0);
                if (XML_Parse(p, (const XML_Char *)data, (int)size, 1)
                    == XML_STATUS_ERROR) {
                    XML_ErrorString(XML_GetErrorCode(p));
                }
                XML_GetCurrentLineNumber(p);
                if (size % 2) { XML_ParserReset(p, NULL); }
            }
        "#;
        let traces = mine_protocol_traces(text);
        let trace = traces
            .iter()
            .find(|trace| trace.first().is_some_and(|call| call.receiver == "p"))
            .expect("parser trace");
        let names = trace
            .iter()
            .map(|call| call.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            [
                "XML_Parse",
                "XML_Parse",
                "XML_GetErrorCode",
                "XML_ErrorString",
                "XML_GetCurrentLineNumber",
                "XML_ParserReset"
            ]
        );
        assert_eq!(trace[0].arguments[3], "0");
        assert_eq!(trace[1].arguments[3], "1");
        assert_eq!(trace[5].arguments[1], "NULL");
        assert_eq!(
            trace[5].input_condition,
            Some(MinedProtocolInputCondition {
                source: MinedProtocolInputSource::Size {
                    input_name: "size".to_owned(),
                },
                transform: MinedProtocolInputTransform::Modulo(2),
                comparison: MinedProtocolComparison::NotEqual,
                value: "0".to_owned(),
            })
        );
        let condition = trace[2]
            .condition
            .as_ref()
            .expect("error accessor retains parse-status guard");
        assert_eq!(condition.producer_name, "XML_Parse");
        assert_eq!(condition.producer_receiver, "p");
        assert_eq!(condition.comparison, MinedProtocolComparison::Equal);
        assert_eq!(condition.value, "XML_STATUS_ERROR");
        assert!(!trace[3].receiver_is_direct);
        assert_eq!(trace[3].receiver, "p");
        assert_eq!(trace[3].arguments, ["XML_GetErrorCode(p)"]);
        assert_eq!(trace[3].condition.as_ref(), Some(condition));
    }

    #[test]
    fn protocol_condition_rejects_local_and_compound_values() {
        let traces = mine_protocol_traces(
            "parse(p); if (parse(p) != local_status) { inspect(p); } finish(p);",
        );
        let inspect = traces[0]
            .iter()
            .find(|call| call.name == "inspect")
            .unwrap();
        assert!(inspect.condition.is_none());
        assert_eq!(
            safe_protocol_constant("ARCHIVE_EOF").as_deref(),
            Some("ARCHIVE_EOF")
        );
        assert_eq!(safe_protocol_constant("some_local"), None);
        assert_eq!(safe_protocol_constant("STATUS + 1"), None);
    }

    #[test]
    fn protocol_predicates_cover_ranges_bytes_masks_and_result_flags() {
        let traces = mine_protocol_traces(
            "parse(p, data, size);\n\
             if (size > 4 && (data[0] & 7) == 3) { inspect(p); }\n\
             if ((status(p) & STATUS_MASK) >= STATUS_READY) { drain(p); }\n\
             finish(p);",
        );
        let trace = traces
            .iter()
            .find(|trace| trace.first().is_some_and(|call| call.receiver == "p"))
            .expect("predicate trace");
        let inspect = trace.iter().find(|call| call.name == "inspect").unwrap();
        assert_eq!(
            inspect.input_condition,
            Some(MinedProtocolInputCondition {
                source: MinedProtocolInputSource::Byte {
                    input_name: "data".to_owned(),
                    index: 0,
                },
                transform: MinedProtocolInputTransform::BitAnd(7),
                comparison: MinedProtocolComparison::Equal,
                value: "3".to_owned(),
            })
        );
        let drain = trace.iter().find(|call| call.name == "drain").unwrap();
        assert_eq!(
            drain.condition,
            Some(MinedProtocolCondition {
                producer_name: "status".to_owned(),
                producer_receiver: "p".to_owned(),
                bitmask: Some("STATUS_MASK".to_owned()),
                comparison: MinedProtocolComparison::GreaterEqual,
                value: "STATUS_READY".to_owned(),
            })
        );
    }

    #[test]
    fn protocol_else_arms_receive_inverse_input_guards() {
        let traces = mine_protocol_traces(
            r#"
                void drive(Parser p, const unsigned char *data, size_t size) {
                    if (size % 2) {
                        parse(p, data, size, MODE_STREAM);
                    } else {
                        parse(p, data, size, MODE_FINAL);
                    }
                    finish(p);
                }
            "#,
        );
        let trace = traces
            .iter()
            .find(|trace| trace.first().is_some_and(|call| call.receiver == "p"))
            .expect("branching protocol trace");
        let parses = trace
            .iter()
            .filter(|call| call.name == "parse")
            .collect::<Vec<_>>();
        assert_eq!(parses.len(), 2);
        assert_eq!(
            parses[0].input_condition,
            Some(MinedProtocolInputCondition {
                source: MinedProtocolInputSource::Size {
                    input_name: "size".to_owned(),
                },
                transform: MinedProtocolInputTransform::Modulo(2),
                comparison: MinedProtocolComparison::NotEqual,
                value: "0".to_owned(),
            })
        );
        assert_eq!(
            parses[1].input_condition,
            Some(MinedProtocolInputCondition {
                source: MinedProtocolInputSource::Size {
                    input_name: "size".to_owned(),
                },
                transform: MinedProtocolInputTransform::Modulo(2),
                comparison: MinedProtocolComparison::Equal,
                value: "0".to_owned(),
            })
        );
    }

    #[test]
    fn protocol_else_arms_receive_inverse_result_guards() {
        let traces = mine_protocol_traces(
            r#"
                void drive(Parser p) {
                    if (parse(p) >= STATUS_READY) {
                        consume(p);
                    } else {
                        recover(p);
                    }
                    finish(p);
                }
            "#,
        );
        let trace = traces
            .iter()
            .find(|trace| trace.first().is_some_and(|call| call.receiver == "p"))
            .expect("branching protocol trace");
        assert_eq!(
            trace
                .iter()
                .find(|call| call.name == "consume")
                .and_then(|call| call.condition.as_ref())
                .map(|condition| condition.comparison),
            Some(MinedProtocolComparison::GreaterEqual)
        );
        assert_eq!(
            trace
                .iter()
                .find(|call| call.name == "recover")
                .and_then(|call| call.condition.as_ref())
                .map(|condition| condition.comparison),
            Some(MinedProtocolComparison::Less)
        );
    }

    #[test]
    fn protocol_calls_in_comments_are_ignored() {
        let traces =
            mine_protocol_traces("use(p); /* destroy(p); */ step(p); // close(p);\nfinish(p);");
        let names = traces[0]
            .iter()
            .map(|call| call.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["use", "step", "finish"]);
    }

    #[test]
    fn protocol_traces_never_stitch_same_named_locals_across_functions() {
        let traces = mine_protocol_traces(
            r#"
                void first_scope(Parser p) { configure(p); parse(p); }
                void second_scope(Parser p) { reset(p); }
            "#,
        );
        assert_eq!(traces.len(), 1);
        assert_eq!(
            traces[0]
                .iter()
                .map(|call| call.name.as_str())
                .collect::<Vec<_>>(),
            ["configure", "parse"]
        );
    }

    #[test]
    fn c_field_preconditions_are_safe_receiver_local_and_pre_call() {
        let initializers = mine_receiver_field_initializers(
            "png_image image; image.version = PNG_IMAGE_VERSION; other.flags = FLAGS; \
             image.width = local_width; image.height += 1;",
            "image",
        );
        assert_eq!(
            initializers,
            vec![MinedCFieldInitializer {
                field: "version".to_owned(),
                value: "PNG_IMAGE_VERSION".to_owned(),
            }]
        );
    }

    #[test]
    fn project_example_supplies_pre_call_handle_field_initializer() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".git")).unwrap();
        std::fs::create_dir(project.path().join("examples")).unwrap();
        let implementation = project.path().join("parser.c");
        std::fs::write(&implementation, "int parse(void) { return 0; }\n").unwrap();
        std::fs::write(
            project.path().join("examples/read.c"),
            r#"
                void read_one(const unsigned char *data, unsigned long size) {
                    image_t image;
                    image.version = IMAGE_API_VERSION;
                    image.width = 0;
                    if (image_begin_read_from_file(&image, "input")) {
                        image.format = IMAGE_RGBA;
                    }
                }
            "#,
        )
        .unwrap();

        assert_eq!(
            c_handle_field_initializers_for(&implementation, "image_begin_read_from_memory"),
            vec![
                MinedCFieldInitializer {
                    field: "version".to_owned(),
                    value: "IMAGE_API_VERSION".to_owned(),
                },
                MinedCFieldInitializer {
                    field: "width".to_owned(),
                    value: "0".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn output_drain_requires_loop_output_cleanup_and_terminal_field() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".git")).unwrap();
        std::fs::create_dir(project.path().join("tests")).unwrap();
        let implementation = project.path().join("parser.c");
        std::fs::write(&implementation, "int implementation(void) { return 0; }\n").unwrap();
        std::fs::write(
            project.path().join("tests/drain.c"),
            r#"
                void drain(parser_t *parser) {
                    event_t event;
                    while (1) {
                        if (!parser_next(parser, &event)) break;
                        int done = event.type == EVENT_STREAM_END;
                        event_delete(&event);
                        if (done) break;
                    }
                }
            "#,
        )
        .unwrap();

        assert_eq!(
            c_output_drain_protocol_for(&implementation, "parser_next"),
            Some(MinedCOutputDrainProtocol {
                output_argument: 0,
                cleanup_name: "event_delete".to_owned(),
                terminal_field: "type".to_owned(),
                terminal_value: "EVENT_STREAM_END".to_owned(),
            })
        );
    }

    #[test]
    fn helper_protocols_are_inlined_with_formal_to_actual_substitution() {
        let traces = mine_protocol_traces(
            r#"
                static void drive(Parser p, const unsigned char *data, size_t size) {
                    API_Setup(p);
                    API_Parse(p, data, size);
                }
                int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
                    drive(parent, data, size);
                    drive(child, data, size);
                    return 0;
                }
            "#,
        );
        for receiver in ["parent", "child"] {
            let trace = traces
                .iter()
                .find(|trace| trace[0].receiver == receiver)
                .expect("expanded helper trace");
            assert_eq!(trace[0].name, "API_Setup");
            assert_eq!(trace[1].name, "API_Parse");
            assert_eq!(trace[1].arguments, [receiver, "data", "size"]);
        }
    }

    #[test]
    fn protocol_macros_are_folded_to_safe_bounded_integer_literals() {
        let traces = mine_protocol_traces(
            r#"
                #define FINAL_FLAG (1u)
                #define BASE_FEATURE (1u << 2)
                #define FEATURES (BASE_FEATURE | FINAL_FLAG)
                void drive(Parser p, const unsigned char *data, size_t size) {
                    API_Configure(p, FEATURES);
                    API_Parse(p, data, size, FINAL_FLAG);
                }
            "#,
        );
        let trace = traces
            .iter()
            .find(|trace| trace[0].receiver == "p")
            .expect("folded protocol trace");
        assert_eq!(trace[0].arguments[1], "5");
        assert_eq!(trace[1].arguments[3], "1u");
    }

    #[test]
    fn helper_substitution_never_rewrites_string_or_character_contents() {
        let call = MinedProtocolCall {
            name: "API_Parse".to_owned(),
            receiver: "p".to_owned(),
            receiver_is_direct: true,
            arguments: vec!["p".to_owned(), "\"p\"".to_owned(), "'p'".to_owned()],
            assigned_to: None,
            source_expression: "API_Parse(p, \"p\", 'p')".to_owned(),
            condition: None,
            input_condition: None,
        };
        let mapped = substitute_protocol_call(call, &[("p", "child")]);
        assert_eq!(mapped.arguments, ["child", "\"p\"", "'p'"]);
        assert_eq!(mapped.source_expression, "API_Parse(child, \"p\", 'p')");
    }

    #[test]
    fn cpp_member_protocol_keeps_order_scope_literals_and_pointer_receivers() {
        let traces = mine_cpp_protocol_traces(
            r#"
                #define FINISH (1u << 1)
                void first(Parser &parser, const char *data, size_t size) {
                    parser.configure(7);
                    parser.parse(data, size, FINISH);
                    parser.finish();
                }
                void unrelated(Parser *parser) { parser->reset(); }
            "#,
        );
        assert_eq!(traces.len(), 1, "one-call scopes are not protocols");
        assert_eq!(
            traces[0]
                .iter()
                .map(|call| call.name.as_str())
                .collect::<Vec<_>>(),
            ["configure", "parse", "finish"]
        );
        assert_eq!(traces[0][1].arguments, ["data", "size", "2"]);
    }

    #[test]
    fn root_level_test_source_supplies_cpp_protocol_evidence() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".git")).unwrap();
        let implementation = project.path().join("parser.cpp");
        std::fs::write(&implementation, "void implementation() {}\n").unwrap();
        std::fs::write(
            project.path().join("xmltest.cpp"),
            r#"
                void example(Parser &parser, const char *data, size_t size) {
                    parser.Parse(data, size);
                    parser.ErrorID();
                }
            "#,
        )
        .unwrap();

        assert_eq!(
            project_root_of(&implementation).as_deref(),
            Some(project.path())
        );
        let traces = cpp_protocol_traces_for(&implementation);
        assert!(traces.iter().any(|trace| {
            trace
                .iter()
                .map(|call| call.name.as_str())
                .eq(["Parse", "ErrorID"])
        }));
    }

    #[test]
    fn reused_cpp_local_name_does_not_stitch_object_lifetimes() {
        let traces = mine_cpp_protocol_traces(
            r#"
                int main() {
                    { Document doc; doc.Parse(first); doc.ErrorID(); }
                    { Document doc; doc.Parse(second); doc.Clear(); }
                }
            "#,
        );
        let names = traces
            .iter()
            .map(|trace| {
                trace
                    .iter()
                    .map(|call| call.name.as_str())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&vec!["Parse", "ErrorID"]));
        assert!(names.contains(&vec!["Parse", "Clear"]));
    }

    #[test]
    fn rust_member_protocol_uses_the_same_scoped_ordered_ir() {
        let traces = mine_cpp_protocol_traces(
            r#"
                fn fuzz(data: &[u8]) {
                    parser.configure(7);
                    parser.parse(data);
                    parser.finish();
                }
                fn other() { parser.reset(); }
            "#,
        );
        assert_eq!(traces.len(), 1);
        assert_eq!(
            traces[0]
                .iter()
                .map(|call| call.name.as_str())
                .collect::<Vec<_>>(),
            ["configure", "parse", "finish"]
        );
    }

    #[test]
    fn assigned_constructor_objects_are_retained_for_topology_mining() {
        let clean = strip_c_comments(
            r#"
                XML_Parser namespaceParser = XML_ParserCreateNS(NULL, '!');
                XML_Parser externalEntityParser
                    = XML_ExternalEntityParserCreate(parentParser, "e1", NULL);
                if (status == XML_STATUS_OK) use(status);
            "#,
        );
        let calls = protocol_calls(&clean);
        let namespace = calls
            .iter()
            .find(|call| call.name == "XML_ParserCreateNS")
            .unwrap();
        let child = calls
            .iter()
            .find(|call| call.name == "XML_ExternalEntityParserCreate")
            .unwrap();
        assert_eq!(namespace.assigned_to.as_deref(), Some("namespaceParser"));
        assert_eq!(child.assigned_to.as_deref(), Some("externalEntityParser"));
        assert_eq!(child.arguments, ["parentParser", "\"e1\"", "NULL"]);
        assert!(calls
            .iter()
            .find(|call| call.name == "use")
            .unwrap()
            .assigned_to
            .is_none());
    }

    #[test]
    fn registered_callback_body_exposes_only_stateful_action_calls() {
        let text = r#"
            static void on_data(void *user, const char *s, int n) {
                Parser p = (Parser)user;
                observe(s);
                if (n > 1) API_StopParser(p, s[0] == 'r');
            }
            void drive(Parser p) {
                API_SetCharacterDataHandler(p, on_data);
                API_Parse(p, "x", 1);
            }
        "#;
        let clean = strip_c_comments(text);
        let registered = protocol_calls(&clean)
            .into_iter()
            .filter(|call| call.name.contains("Handler"))
            .flat_map(|call| call.arguments.into_iter().skip(1))
            .filter_map(|arg| leading_expression_identifier(&arg))
            .collect::<BTreeSet<_>>();
        let body = function_body_for(&clean, registered.iter().next().unwrap()).unwrap();
        let action_names = protocol_calls(body)
            .into_iter()
            .filter(|call| call.name.to_ascii_lowercase().contains("stop"))
            .map(|call| call.name)
            .collect::<Vec<_>>();
        assert_eq!(action_names, ["API_StopParser"]);
    }

    #[test]
    fn initializer_polarity_is_mined_from_boolean_success_call_sites() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("src")).unwrap();
        std::fs::create_dir(root.path().join("tests")).unwrap();
        let target = root.path().join("src/parser.c");
        std::fs::write(&target, "int parse(void *p) { return p != 0; }").unwrap();
        std::fs::write(
            root.path().join("tests/parser_test.c"),
            "void test(void) { parser_t p; assert(yaml_parser_initialize(&p)); }",
        )
        .unwrap();
        assert!(initializer_success_is_nonzero(
            &target,
            "yaml_parser_initialize"
        ));
        assert!(!initializer_success_is_nonzero(&target, "errno_style_init"));

        std::fs::write(
            &target,
            "int begin(image *p) { if (private_init(p) != 0) return 1; return 0; }",
        )
        .unwrap();
        assert!(
            !initializer_success_is_nonzero(&target, "private_init"),
            "an `!= 0` error branch is evidence for errno-style zero success"
        );
    }

    #[test]
    fn seeds_are_mined_from_test_data_but_never_from_source() {
        // libarchive, libexpat and zlib all ship real inputs beside their tests.
        // A parser reached through random bytes bounces off the header check;
        // the same harness given one real archive starts inside the format.
        let root = std::env::temp_dir().join(format!("govfuzz-seedmine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("tests/testdata")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("tests/testdata/sample.tar"), b"ustar-ish bytes").unwrap();
        std::fs::write(root.join("tests/testdata/doc.xml"), b"<x/>").unwrap();
        std::fs::write(root.join("tests/testdata/README.md"), b"notes").unwrap();
        std::fs::write(root.join("tests/helper.c"), b"int helper(void){return 0;}").unwrap();
        // Shipped source is not test data and must not be harvested.
        std::fs::write(root.join("src/lib.c"), b"int lib(void){return 0;}").unwrap();

        let seeds = mine_seed_corpus(&root);
        let names: Vec<String> = seeds
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert!(names.contains(&"sample.tar".to_owned()), "{names:?}");
        assert!(names.contains(&"doc.xml".to_owned()), "{names:?}");
        // Source and prose are not seeds: feeding the fuzzer its own target's
        // source spends budget on inputs the parser was never going to accept.
        assert!(!names.contains(&"helper.c".to_owned()), "{names:?}");
        assert!(!names.contains(&"README.md".to_owned()), "{names:?}");
        assert!(!names.contains(&"lib.c".to_owned()), "{names:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_oversized_or_empty_file_is_not_a_seed() {
        let root = std::env::temp_dir().join(format!("govfuzz-seedcap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("tests/corpus")).unwrap();
        std::fs::write(root.join("tests/corpus/empty.bin"), b"").unwrap();
        std::fs::write(
            root.join("tests/corpus/huge.bin"),
            vec![0u8; (MAX_SEED_BYTES + 1) as usize],
        )
        .unwrap();
        std::fs::write(root.join("tests/corpus/ok.bin"), b"fine").unwrap();

        let names: Vec<String> = mine_seed_corpus(&root)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["ok.bin".to_owned()], "{names:?}");

        let _ = std::fs::remove_dir_all(&root);
    }
}
