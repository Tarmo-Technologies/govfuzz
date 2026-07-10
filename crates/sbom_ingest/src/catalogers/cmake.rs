// SPDX-License-Identifier: Apache-2.0

//! CMake build-system cataloger.
//!
//! A CMake C/C++ project declares its own identity in `project(Name VERSION
//! x.y.z ...)` and its dependencies via `find_package(Name [version] ...)`.
//! Without this cataloger a pure-CMake project's identity and declared deps are
//! invisible. The scan is bounded and regex-free.
//!
//! The `project()` identity is tagged `component_type = "source"` so
//! `governance::primary_self_component` adopts it as the CycloneDX
//! `metadata.component`. Components use `ecosystem = "generic"` with `pkg:generic`
//! purls so a CMake dependency and a `SourceObserved` C library collapse via a
//! shared purl.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::Component;
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::fs;
use std::path::Path;

pub struct CMakeCataloger;

impl Cataloger for CMakeCataloger {
    fn ecosystem(&self) -> &str {
        "generic"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("CMakeLists.txt").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();
        for path in ctx.files_named("CMakeLists.txt") {
            let rel = relative_path(&ctx.root, path);
            let source = read_bounded(path)?;
            if let Some(self_component) = cmake_project_component(&source, &rel) {
                out.push(self_component);
            }
            out.extend(cmake_find_package_components(&source, &rel));
        }
        Ok(out)
    }
}

/// The project's OWN identity from `project(Name [VERSION x.y.z] ...)`.
fn cmake_project_component(source: &str, relative: &str) -> Option<Component> {
    let args = extract_calls(source, "project").into_iter().next()?;
    let tokens = tokenize(&args);
    let name = tokens.first()?.clone();
    if name.is_empty() || name.contains("${") {
        return None;
    }
    let version = cmake_keyword_version(&tokens, "VERSION");
    let purl_val = version.as_deref().map(|v| purl::generic(&name, v));
    Some(Component {
        component_ref: String::new(),
        name,
        group: None,
        version,
        ecosystem: "generic".to_owned(),
        component_type: "source".to_owned(),
        supplier: None,
        license: None,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "high".to_owned(),
        matching_method: "cmake_project".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, relative.to_owned())],
        runtime_harnesses: Vec::new(),
    })
}

/// Declared `find_package(Name [version] ...)` components. A version is recorded
/// only when the second token is a bare version (digits and dots).
fn cmake_find_package_components(source: &str, relative: &str) -> Vec<Component> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for args in extract_calls(source, "find_package") {
        let tokens = tokenize(&args);
        let Some(name) = tokens.first().cloned() else {
            continue;
        };
        if name.is_empty() || name.contains("${") || !seen.insert(name.clone()) {
            continue;
        }
        let version = tokens.get(1).and_then(|t| bare_version(t));
        let purl_val = version.as_deref().map(|v| purl::generic(&name, v));
        let source_loc = format!("{relative}:find_package({name})");
        out.push(Component {
            component_ref: String::new(),
            name,
            group: None,
            version,
            ecosystem: "generic".to_owned(),
            component_type: "library".to_owned(),
            supplier: None,
            license: None,
            purl: purl_val,
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "medium".to_owned(),
            matching_method: "cmake_find_package".to_owned(),
            evidence: vec![Evidence::new(EvidenceKind::Declared, source_loc)],
            runtime_harnesses: Vec::new(),
        });
    }
    out
}

/// The token immediately following an uppercase `keyword` (e.g. `VERSION`), when
/// it is a bare version.
fn cmake_keyword_version(tokens: &[String], keyword: &str) -> Option<String> {
    let pos = tokens.iter().position(|t| t == keyword)?;
    tokens.get(pos + 1).and_then(|t| bare_version(t))
}

/// `Some(v)` only when `t` is a bare version (digits and dots) — rejects CMake
/// keywords (`REQUIRED`, `COMPONENTS`) and variable refs in the version slot.
fn bare_version(t: &str) -> Option<String> {
    if !t.is_empty()
        && t.starts_with(|c: char| c.is_ascii_digit())
        && t.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        Some(t.to_owned())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// CMake call-syntax scanning (bounded, regex-free)
// ---------------------------------------------------------------------------

/// Return the argument text of every `name(...)` call, matched on an identifier
/// boundary. Quotes and `#` line comments are respected; parens are balanced.
fn extract_calls(source: &str, name: &str) -> Vec<String> {
    let needle = format!("{name}(");
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(&needle) {
        let idx = search_from + rel;
        let open = idx + needle.len();
        search_from = open;
        let boundary =
            idx == 0 || !(bytes[idx - 1].is_ascii_alphanumeric() || bytes[idx - 1] == b'_');
        if !boundary {
            continue;
        }
        if let Some(args) = balanced_parens(&source[open..]) {
            out.push(args);
        }
    }
    out
}

/// Collect the text up to the matching `)`, honouring quotes and `#` comments.
/// `s` starts AFTER the open `(`.
fn balanced_parens(s: &str) -> Option<String> {
    let mut depth = 1usize;
    let mut quote: Option<char> = None;
    let mut buf = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            buf.push(c);
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => {
                quote = Some(c);
                buf.push(c);
            }
            '(' => {
                depth += 1;
                buf.push(c);
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(buf);
                }
                buf.push(c);
            }
            '#' => {
                while let Some(&n) = chars.peek() {
                    if n == '\n' {
                        break;
                    }
                    chars.next();
                }
            }
            _ => buf.push(c),
        }
    }
    None
}

/// Split CMake call arguments into whitespace-separated tokens, treating a
/// quoted string as one token (quotes stripped) and skipping `#` comments.
fn tokenize(args: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = args.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                cur.push(c);
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '#' => {
                while let Some(&n) = chars.peek() {
                    if n == '\n' {
                        break;
                    }
                    chars.next();
                }
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_bounded(path: &Path) -> Result<String, CatalogError> {
    let bytes = fs::read(path).map_err(|source| CatalogError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let slice = &bytes[..bytes.len().min(4 * 1024 * 1024)];
    Ok(String::from_utf8_lossy(slice).into_owned())
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(path_string)
        .unwrap_or_else(|_| path_string(path))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_ctx(files: &[(&str, &str)]) -> (tempfile::TempDir, CatalogContext) {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let mut paths = Vec::new();
        for (name, body) in files {
            let p = dir.path().join(name);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::File::create(&p)
                .unwrap()
                .write_all(body.as_bytes())
                .unwrap();
            paths.push(p);
        }
        let ctx = CatalogContext::new(dir.path().to_path_buf(), paths);
        (dir, ctx)
    }

    #[test]
    fn project_self_component_carries_name_and_version() {
        let (_d, ctx) = temp_ctx(&[(
            "CMakeLists.txt",
            "cmake_minimum_required(VERSION 3.16)\nproject(MyLib VERSION 2.3.4 LANGUAGES CXX)\n",
        )]);
        let out = CMakeCataloger.catalog(&ctx).unwrap();
        let self_comp = out
            .iter()
            .find(|c| c.matching_method == "cmake_project")
            .expect("project() self-component must be emitted");
        assert_eq!(self_comp.name, "MyLib");
        assert_eq!(self_comp.version.as_deref(), Some("2.3.4"));
        assert_eq!(self_comp.component_type, "source");
        assert_eq!(self_comp.purl.as_deref(), Some("pkg:generic/mylib@2.3.4"));
    }

    #[test]
    fn cmake_minimum_required_is_not_the_project() {
        // `cmake_minimum_required(VERSION 3.16)` must not be parsed as project().
        let (_d, ctx) = temp_ctx(&[(
            "CMakeLists.txt",
            "cmake_minimum_required(VERSION 3.16)\nproject(Real VERSION 1.0.0)\n",
        )]);
        let out = CMakeCataloger.catalog(&ctx).unwrap();
        let projects: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "cmake_project")
            .collect();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "Real");
        assert_eq!(projects[0].version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn find_package_with_and_without_version() {
        let (_d, ctx) = temp_ctx(&[(
            "CMakeLists.txt",
            "project(App)\n\
             find_package(Boost 1.70 REQUIRED COMPONENTS system)\n\
             find_package(Threads REQUIRED)\n",
        )]);
        let out = CMakeCataloger.catalog(&ctx).unwrap();
        let boost = out
            .iter()
            .find(|c| c.name == "Boost" && c.matching_method == "cmake_find_package")
            .expect("Boost present");
        assert_eq!(boost.version.as_deref(), Some("1.70"));
        assert_eq!(boost.purl.as_deref(), Some("pkg:generic/boost@1.70"));
        let threads = out
            .iter()
            .find(|c| c.name == "Threads" && c.matching_method == "cmake_find_package")
            .expect("Threads present");
        assert!(threads.version.is_none(), "REQUIRED is not a version");
    }

    #[test]
    fn project_with_variable_name_is_skipped() {
        let (_d, ctx) = temp_ctx(&[("CMakeLists.txt", "project(${PROJ_NAME} VERSION 1.0.0)\n")]);
        let out = CMakeCataloger.catalog(&ctx).unwrap();
        assert!(
            out.iter().all(|c| c.matching_method != "cmake_project"),
            "an unresolved ${{...}} project name must not be emitted"
        );
    }

    #[test]
    fn detect_gates_on_cmakelists() {
        let with = CatalogContext::new("/r".into(), vec![PathBuf::from("/r/CMakeLists.txt")]);
        assert!(CMakeCataloger.detect(&with));
        let without = CatalogContext::new("/r".into(), vec![PathBuf::from("/r/Makefile")]);
        assert!(!CMakeCataloger.detect(&without));
    }
}
