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

use std::collections::BTreeMap;
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
pub(crate) fn for_source(source_path: &Path) -> MinedRecipes {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<std::path::PathBuf, MinedRecipes>>,
    > = std::sync::OnceLock::new();
    let Some(root) = project_root_of(source_path) else {
        return MinedRecipes::new();
    };
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(hit) = guard.get(&root) {
            return hit.clone();
        }
    }
    let mined = mine(&root, &["cpp", "cc", "cxx", "c", "hpp", "h"]);
    if let Ok(mut guard) = cache.lock() {
        guard.insert(root, mined.clone());
    }
    mined
}

/// The nearest ancestor of `source_path` that actually contains an example-ish
/// directory. Bounded, so a source deep in a tree cannot walk to the filesystem
/// root looking for one.
fn project_root_of(source_path: &Path) -> Option<std::path::PathBuf> {
    let mut current = source_path.parent()?;
    for _ in 0..8 {
        if !recipe_dirs_directly_under(current).is_empty() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
    None
}

fn recipe_dirs_directly_under(dir: &Path) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter(|entry| {
            RECIPE_DIRS.contains(
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
}
