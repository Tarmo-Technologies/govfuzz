// SPDX-License-Identifier: Apache-2.0
//! Module search paths for the interpreted lanes.
//!
//! An interpreted target is loaded by its own runtime, so the runtime has to be
//! able to resolve the target's `require`/`import` of its SIBLINGS. Pointing it
//! at the file's own directory and the project root is not enough for the two
//! layouts most real projects use:
//!
//! * **package root** — `actionpack/lib/abstract_controller/collector.rb` says
//!   `require "action_dispatch/http/mime_type"`, which resolves only with
//!   `actionpack/lib` on the path, not the file's directory and not the repo
//!   root.
//! * **monorepo of packages** — that same file then reaches into
//!   `activesupport/lib`, a sibling package elsewhere in the tree.
//!
//! Both are in-project code that is present on disk: failing to load it is a
//! recoverable path problem, not a missing dependency. This module collects the
//! roots, nearest-first, so the lane can hand them to the interpreter.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Directory names that conventionally ARE a module root: a file at
/// `<root>/a/b.rb` is the module `a/b`.
const ROOT_DIR_NAMES: &[&str] = &["lib", "src", "lua", "app", "source"];

/// Never search inside these: vendored or generated code costs walk time and
/// can shadow the project's own modules with a stale copy.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "vendor",
    "third_party",
    "thirdparty",
    "target",
    "build",
    "dist",
    "tmp",
    ".venv",
    "venv",
    "__pycache__",
    "site-packages",
    "bower_components",
    "coverage",
];

/// Cap the number of roots handed to the interpreter. A path list that grows
/// with the tree turns every `require` into a linear directory scan, and the
/// nearest roots are the ones that actually resolve.
const MAX_ROOTS: usize = 48;

/// How deep under the project root to look for package roots. Monorepos nest
/// one or two levels (`rails/actionpack/lib`, `packages/core/src`); beyond that
/// the hits are test fixtures.
const MAX_DEPTH: usize = 3;

/// The module search path for a target, nearest-first and de-duplicated.
///
/// Order is significant: the target's own package root must win over a sibling
/// package that happens to define the same module name.
pub(crate) fn module_load_roots(source_root: &Path, target_dir: &Path) -> Vec<PathBuf> {
    let mut ordered: Vec<PathBuf> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let push = |path: PathBuf, ordered: &mut Vec<PathBuf>, seen: &mut BTreeSet<PathBuf>| {
        if path.is_dir() && seen.insert(path.clone()) {
            ordered.push(path);
        }
    };

    // 1. The file's own directory: sibling files loaded by bare name.
    push(target_dir.to_path_buf(), &mut ordered, &mut seen);

    // 2. Every conventional root between the file and the project root, nearest
    //    first — this is the one that resolves `require "action_dispatch/..."`.
    let mut cursor = target_dir;
    loop {
        if is_root_dir_name(cursor) {
            push(cursor.to_path_buf(), &mut ordered, &mut seen);
        }
        if cursor == source_root {
            break;
        }
        match cursor.parent() {
            Some(parent) if parent.starts_with(source_root) || parent == source_root => {
                cursor = parent;
            }
            _ => break,
        }
    }

    // 3. The project root itself: flat layouts and `kong.db.schema`-style
    //    namespaces rooted at the checkout.
    push(source_root.to_path_buf(), &mut ordered, &mut seen);

    // 4. Sibling package roots elsewhere in the tree (`activesupport/lib`).
    for dir in sibling_package_roots(source_root) {
        if ordered.len() >= MAX_ROOTS {
            break;
        }
        push(dir, &mut ordered, &mut seen);
    }

    ordered.truncate(MAX_ROOTS);
    ordered
}

fn is_root_dir_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| ROOT_DIR_NAMES.contains(&name))
}

/// Conventional module roots within `MAX_DEPTH` of the project root, sorted so
/// the result is stable across runs.
fn sibling_package_roots(source_root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    collect_roots(source_root, source_root, 0, &mut found);
    found.sort();
    found
}

fn collect_roots(dir: &Path, source_root: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH || out.len() >= MAX_ROOTS {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= MAX_ROOTS {
            return;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.') || SKIP_DIRS.contains(&name) {
            continue;
        }
        if ROOT_DIR_NAMES.contains(&name) && path != source_root {
            out.push(path.clone());
            // A package root's children are modules, not more roots.
            continue;
        }
        collect_roots(&path, source_root, depth + 1, out);
    }
}

/// The same roots as a single separator-joined string, for `RUBYLIB`,
/// `PERL5LIB`, `PYTHONPATH`, and `NODE_PATH`.
pub(crate) fn join_roots(roots: &[PathBuf], separator: char) -> String {
    roots
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(&separator.to_string())
}

/// The line of an interpreter's stderr that says what actually went wrong.
///
/// Taking the last line yields a backtrace frame (`from -e:1:in '<main>'`) and
/// taking the first yields a banner, so a whole lane's skip reasons collapsed
/// into one useless histogram row. Prefer the first line that names an error,
/// and strip the interpreter's file:line prefix so instances of one cause group
/// together.
pub(crate) fn interpreter_error_line(stderr: &str) -> String {
    let informative = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("from "))
        .find(|line| {
            line.contains("Error")
                || line.contains("error")
                || line.contains("cannot")
                || line.contains("not found")
        })
        .or_else(|| {
            stderr
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && !line.starts_with("from "))
        })
        .unwrap_or("load error");
    strip_location_prefix(informative)
}

/// Drop a leading `path:line:in 'fn':` so the same cause from two files is one
/// histogram row. Only a prefix that really looks like a location is removed.
fn strip_location_prefix(line: &str) -> String {
    let mut rest = line;
    // Ruby/Perl/Lua all lead with `<something>:<digits>:` possibly repeated.
    while let Some(colon) = rest.find(':') {
        let after = &rest[colon + 1..];
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            break;
        }
        let after_digits = &after[digits.len()..];
        let after_digits = after_digits
            .strip_prefix(":in ")
            .and_then(|s| s.split_once(':').map(|(_, tail)| tail))
            .or_else(|| after_digits.strip_prefix(':'))
            .unwrap_or(after_digits);
        rest = after_digits.trim_start();
    }
    rest.trim().to_owned()
}

/// The marker every lane puts in an unloadable-target reason when the cause is a
/// package that is not installed. The run reads it back to record the package as
/// an offline requirement, and the triage reads it to stop advising `--force` —
/// forcing a parameter cannot install a package.
pub(crate) const MISSING_MODULE_MARKER: &str = "missing module `";

/// True when a skip reason says the target could not be loaded because a package
/// is missing, rather than because its signature could not be driven.
pub(crate) fn is_missing_package_reason(reason: &str) -> bool {
    reason.contains(MISSING_MODULE_MARKER)
}

/// The canonical "this target could not be loaded" skip reason.
///
/// One builder for all six interpreted lanes: when the interpreter named the
/// package it could not resolve, the reason carries [`MISSING_MODULE_MARKER`] so
/// the package becomes a named requirement instead of an unreadable stderr line.
/// Lanes that skipped this wording had their largest blocker class filed as
/// "a parameter couldn't be driven" and left `missing-deps` empty.
pub(crate) fn unloadable_reason(subject: &str, stderr: &str) -> String {
    let detail = interpreter_error_line(stderr);
    match missing_module_name(stderr) {
        Some(module) => format!(
            "target `{subject}` is not loadable (skipped cleanly): \
             {MISSING_MODULE_MARKER}{module}` (not in the project and not installed) — {detail}"
        ),
        None => format!("target `{subject}` is not loadable (skipped cleanly): {detail}"),
    }
}

/// PHP's phrasing when a `require` cannot be opened — `require 'vendor/autoload.php'`
/// with no `vendor/`, the shape of every Composer project whose dependencies were
/// never installed. Unlike the other needles it yields a filesystem path, so it is
/// named here and handled separately. Left unmatched it produced an unreadable
/// histogram row and recorded no requirement, on the majority of real PHP trees.
const PHP_REQUIRED_PATH_NEEDLE: &str = "Failed opening required ";

/// The module an interpreter says it could not find, if it named one. Lets a
/// lane report `missing gem "concurrent-ruby"` instead of a raw stderr line,
/// and lets the run record it as an offline requirement.
pub(crate) fn missing_module_name(stderr: &str) -> Option<String> {
    for needle in [
        "cannot load such file -- ", // ruby
        "module '",                  // lua: module 'x' not found
        "Can't locate ",             // perl
        "Cannot find module '",      // node
        "No module named ",          // python
        "Class \"",                  // php
        PHP_REQUIRED_PATH_NEEDLE,
    ] {
        if let Some(at) = stderr.find(needle) {
            // Some interpreters quote the name after the phrase (CPython:
            // `No module named 'werkzeug'`). Without skipping that opening quote
            // the extractor stopped immediately and returned nothing, so the
            // Python needle never fired despite being listed here.
            let rest = &stderr[at + needle.len()..].trim_start_matches(['\'', '"']);
            let name: String = rest
                .chars()
                .take_while(|c| !matches!(c, '\'' | '"' | ' ' | '\n' | '(' | ')'))
                .collect();
            let name = name.trim_end_matches(&[',', '.'][..]).to_owned();
            if !name.is_empty() {
                // Only the required-file needle yields a filesystem path; module
                // names like `Foo/Bar/Baz.pm` must survive intact.
                return Some(if needle == PHP_REQUIRED_PATH_NEEDLE {
                    shorten_required_path(&name)
                } else {
                    name
                });
            }
        }
    }
    None
}

/// Reduce an absolute required-file path to its last two components.
///
/// PHP reports the resolved absolute path (`/home/me/proj/vendor/autoload.php`),
/// which names the same requirement differently on every host and in every
/// checkout — so the manifest and the histogram would never group. `vendor/
/// autoload.php` is the requirement; the prefix is where this box happened to
/// put it. Anything that isn't a path is returned unchanged.
fn shorten_required_path(name: &str) -> String {
    if !name.contains('/') {
        return name.to_owned();
    }
    let parts: Vec<&str> = name.rsplit('/').filter(|p| !p.is_empty()).take(2).collect();
    if parts.len() < 2 {
        return name.trim_start_matches('/').to_owned();
    }
    format!("{}/{}", parts[1], parts[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every interpreted lane must render the same marker when the interpreter
    /// named a package it could not resolve. Python, Node and PHP described the
    /// cause in prose without it, so across a 534-project sweep their largest
    /// blocker class was filed as "a parameter couldn't be driven" and their
    /// `missing-deps` manifests reported no missing dependency at all.
    #[test]
    fn every_interpreter_dialect_yields_the_named_package_marker() {
        let cases = [
            // python
            (
                "flask.cli",
                "ModuleNotFoundError: No module named 'werkzeug'",
                "werkzeug",
            ),
            // node
            (
                "src/index.js",
                "Error: Cannot find module 'lodash'\n    at Module._resolveFilename",
                "lodash",
            ),
            // php
            (
                "App\\Kernel",
                "PHP Fatal error:  Uncaught Error: Class \"Symfony\\Component\\Console\" not found",
                "Symfony\\Component\\Console",
            ),
            // ruby
            (
                "Rails::Command",
                "-e:1:in 'require': cannot load such file -- concurrent/map (LoadError)",
                "concurrent/map",
            ),
            // lua
            ("mod.init", "lua: module 'socket' not found:", "socket"),
            // perl — a multi-component module path must survive intact
            (
                "My::Thing",
                "Can't locate JSON/PP/Boolean.pm in @INC (you may need to install it)",
                "JSON/PP/Boolean.pm",
            ),
            // php composer: the resolved ABSOLUTE path reduces to the requirement,
            // so the same missing vendor/ groups across hosts and checkouts.
            (
                "parse.php",
                "PHP Fatal error:  Uncaught Error: Failed opening required \
                 '/home/me/proj/vendor/autoload.php' (include_path='.:/usr/share/php')",
                "vendor/autoload.php",
            ),
        ];
        for (subject, stderr, package) in cases {
            let reason = unloadable_reason(subject, stderr);
            assert!(
                is_missing_package_reason(&reason),
                "no package marker for {subject}: {reason}"
            );
            assert_eq!(
                missing_module_name(stderr).as_deref(),
                Some(package),
                "wrong package extracted from: {stderr}"
            );
            assert!(
                reason.contains(package),
                "the reason must name the package: {reason}"
            );
            assert!(
                reason.contains(subject),
                "the reason must name the target: {reason}"
            );
        }
    }

    /// A load failure that is NOT a missing package must not claim to be one —
    /// otherwise it would be recorded as a phantom offline requirement.
    #[test]
    fn a_load_error_that_names_no_package_carries_no_package_marker() {
        let reason = unloadable_reason("thing.py", "TypeError: unsupported operand type(s)");
        assert!(!is_missing_package_reason(&reason), "{reason}");
        assert!(reason.contains("TypeError"), "{reason}");
    }

    /// Build a rails-shaped monorepo: two packages, each with a `lib` root.
    fn rails_shaped() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        for sub in [
            "actionpack/lib/abstract_controller",
            "activesupport/lib/active_support",
            "actionpack/test",
            "node_modules/junk/lib",
        ] {
            std::fs::create_dir_all(root.join(sub)).expect("mkdir");
        }
        dir
    }

    #[test]
    fn package_root_of_the_target_comes_before_the_project_root() {
        let dir = rails_shaped();
        let root = dir.path();
        let target_dir = root.join("actionpack/lib/abstract_controller");
        let roots = module_load_roots(root, &target_dir);

        let index = |p: &Path| {
            roots
                .iter()
                .position(|r| r == p)
                .unwrap_or_else(|| panic!("missing root {}: {roots:?}", p.display()))
        };
        // The file's own dir, then ITS package root, then the checkout.
        assert_eq!(roots[0], target_dir, "own directory first: {roots:?}");
        assert!(
            index(&root.join("actionpack/lib")) < index(root),
            "the target's package root must beat the project root: {roots:?}"
        );
    }

    #[test]
    fn sibling_package_roots_are_included_so_cross_package_requires_resolve() {
        let dir = rails_shaped();
        let root = dir.path();
        let roots = module_load_roots(root, &root.join("actionpack/lib/abstract_controller"));
        assert!(
            roots.contains(&root.join("activesupport/lib")),
            "a sibling package's lib must be searchable: {roots:?}"
        );
    }

    #[test]
    fn vendored_trees_are_never_searched() {
        let dir = rails_shaped();
        let root = dir.path();
        let roots = module_load_roots(root, &root.join("actionpack/lib"));
        assert!(
            !roots
                .iter()
                .any(|r| r.starts_with(root.join("node_modules"))),
            "vendored code must not shadow project modules: {roots:?}"
        );
    }

    #[test]
    fn roots_are_unique_and_bounded() {
        let dir = rails_shaped();
        let root = dir.path();
        let roots = module_load_roots(root, &root.join("actionpack/lib"));
        let unique: BTreeSet<_> = roots.iter().collect();
        assert_eq!(unique.len(), roots.len(), "duplicate roots: {roots:?}");
        assert!(roots.len() <= MAX_ROOTS);
    }

    #[test]
    fn a_flat_project_still_gets_its_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("kong/db")).expect("mkdir");
        let roots = module_load_roots(root, &root.join("kong/db"));
        assert!(
            roots.contains(&root.to_path_buf()),
            "namespaced modules resolve from the checkout root: {roots:?}"
        );
    }

    #[test]
    fn join_roots_uses_the_platform_separator() {
        let joined = join_roots(&[PathBuf::from("/a"), PathBuf::from("/b")], ':');
        assert_eq!(joined, "/a:/b");
    }
}
