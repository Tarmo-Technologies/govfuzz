// SPDX-License-Identifier: Apache-2.0

//! Meson build-system cataloger.
//!
//! A Meson C/C++ project declares its own identity in `project('name', ...,
//! version: '...')` and its dependencies via `dependency('name', version: '...')`
//! and `subprojects/*.wrap` files. None of these are otherwise catalogued, so a
//! pure-Meson project's identity (e.g. `tomlplusplus@3.4.0`, MIT) and declared
//! deps would be invisible. This cataloger recovers them with a bounded,
//! regex-free string scan of the `meson.build` call syntax.
//!
//! The project's own `project()` identity is tagged `component_type = "source"`
//! so `governance::primary_self_component` can adopt it as the CycloneDX
//! `metadata.component`. Components use `ecosystem = "generic"` with `pkg:generic`
//! purls — the same scheme the C source cataloger uses, so a Meson dependency and
//! a `SourceObserved` C library collapse via a shared purl.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::Component;
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::fs;
use std::path::Path;

pub struct MesonCataloger;

impl Cataloger for MesonCataloger {
    fn ecosystem(&self) -> &str {
        "generic"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("meson.build").next().is_some() || ctx.files.iter().any(|p| is_wrap(p))
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();

        for path in ctx.files_named("meson.build") {
            let rel = relative_path(&ctx.root, path);
            let source = read_bounded(path)?;
            if let Some(self_component) = meson_project_component(&source, &rel) {
                out.push(self_component);
            }
            out.extend(meson_dependency_components(&source, &rel));
        }

        // subprojects/*.wrap — declared subproject dependencies.
        for path in ctx.files.iter().filter(|p| is_wrap(p)) {
            let rel = relative_path(&ctx.root, path);
            let source = read_bounded(path)?;
            if let Some(component) = wrap_component(path, &source, &rel) {
                out.push(component);
            }
        }

        Ok(out)
    }
}

/// The project's OWN identity from `project('name', ..., version: '...',
/// license: '...')`. Tagged `source` so the renderer adopts it as
/// metadata.component.
fn meson_project_component(source: &str, relative: &str) -> Option<Component> {
    let args = extract_calls(source, "project").into_iter().next()?;
    let name = first_quoted(&args)?;
    if name.is_empty() || name.contains("@0@") {
        return None;
    }
    let version = keyword_quoted(&args, "version").and_then(bare_version);
    let license = keyword_quoted(&args, "license").filter(|s| !s.is_empty());
    let purl_val = version.as_deref().map(|v| purl::generic(&name, v));
    Some(Component {
        component_ref: String::new(),
        name,
        group: None,
        version,
        ecosystem: "generic".to_owned(),
        component_type: "source".to_owned(),
        supplier: None,
        license,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "high".to_owned(),
        matching_method: "meson_project".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, relative.to_owned())],
        runtime_harnesses: Vec::new(),
    })
}

/// Declared `dependency('name'[, version: '...'])` components. A version is only
/// recorded when it is a bare pin (no comparator) — Meson version: constraints
/// are usually ranges, which stay version-less.
fn meson_dependency_components(source: &str, relative: &str) -> Vec<Component> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for args in extract_calls(source, "dependency") {
        let Some(name) = first_quoted(&args) else {
            continue;
        };
        if name.is_empty() || name.contains("@0@") || !seen.insert(name.clone()) {
            continue;
        }
        let version = keyword_quoted(&args, "version").and_then(bare_version);
        let purl_val = version.as_deref().map(|v| purl::generic(&name, v));
        let source_loc = format!("{relative}:dependency({name})");
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
            matching_method: "meson_dependency".to_owned(),
            evidence: vec![Evidence::new(EvidenceKind::Declared, source_loc)],
            runtime_harnesses: Vec::new(),
        });
    }
    out
}

/// A `subprojects/<name>.wrap` declared dependency. The name is the file stem;
/// a version is recovered from a `directory = <name>-<version>` line when present.
fn wrap_component(path: &Path, source: &str, relative: &str) -> Option<Component> {
    let stem = path.file_stem().and_then(|s| s.to_str())?.to_owned();
    if stem.is_empty() {
        return None;
    }
    let version = wrap_version(source, &stem);
    let purl_val = version.as_deref().map(|v| purl::generic(&stem, v));
    Some(Component {
        component_ref: String::new(),
        name: stem,
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
        identity_confidence: "low".to_owned(),
        matching_method: "meson_wrap".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, relative.to_owned())],
        runtime_harnesses: Vec::new(),
    })
}

/// Best-effort version from a wrap file: a `directory = <stem>-<version>` line.
fn wrap_version(source: &str, stem: &str) -> Option<String> {
    for line in source.lines() {
        let line = line.trim();
        let Some(value) = line.strip_prefix("directory") else {
            continue;
        };
        let value = value.trim_start().strip_prefix('=')?.trim();
        // `<stem>-<version>` (or `<anything>-<version>` ending the dir name).
        if let Some(rest) = value.strip_prefix(&format!("{stem}-")) {
            if rest.starts_with(|c: char| c.is_ascii_digit()) {
                return Some(rest.to_owned());
            }
        }
        if let Some((_, tail)) = value.rsplit_once('-') {
            if tail.starts_with(|c: char| c.is_ascii_digit()) {
                return Some(tail.to_owned());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Meson call-syntax scanning (bounded, regex-free)
// ---------------------------------------------------------------------------

/// Return the argument text of every `name(...)` call (matched on an identifier
/// boundary so `subproject(` does not match `project(`). Quotes and `#` line
/// comments are respected; nested parens are balanced.
fn extract_calls(source: &str, name: &str) -> Vec<String> {
    let needle = format!("{name}(");
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(&needle) {
        let idx = search_from + rel;
        let open = idx + needle.len();
        search_from = open;
        // Identifier boundary before the name.
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

/// Collect the text inside a `(` whose matching `)` we scan for, honouring quotes
/// (with backslash escapes) and `#` line comments. `s` starts AFTER the open `(`.
fn balanced_parens(s: &str) -> Option<String> {
    let mut depth = 1usize;
    let mut quote: Option<char> = None;
    let mut buf = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            buf.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    buf.push(n);
                }
                continue;
            }
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => {
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

/// The contents of the first single- or double-quoted string in `s`.
fn first_quoted(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        if c == b'\'' || c == b'"' {
            let rest = &s[i + 1..];
            let end = rest.find(c as char)?;
            return Some(rest[..end].to_owned());
        }
    }
    None
}

/// The first quoted string following a `keyword:` keyword argument.
fn keyword_quoted(args: &str, keyword: &str) -> Option<String> {
    let bytes = args.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = args[search_from..].find(keyword) {
        let idx = search_from + rel;
        search_from = idx + keyword.len();
        let before_ok =
            idx == 0 || !(bytes[idx - 1].is_ascii_alphanumeric() || bytes[idx - 1] == b'_');
        let after = args[idx + keyword.len()..].trim_start();
        if before_ok {
            if let Some(value) = after.strip_prefix(':') {
                return first_quoted(value);
            }
        }
    }
    None
}

/// `Some(v)` only when `v` is a bare version (digits and dots, no comparator),
/// so a Meson `version:` range constraint never becomes a concrete version.
fn bare_version(v: String) -> Option<String> {
    let v = v.trim().to_owned();
    if v.is_empty() {
        return None;
    }
    if v.starts_with(|c: char| c.is_ascii_digit())
        && v.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        Some(v)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_wrap(path: &Path) -> bool {
    let is_wrap_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("wrap"))
        .unwrap_or(false);
    let in_subprojects = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(|n| n == "subprojects")
        .unwrap_or(false);
    is_wrap_ext && in_subprojects
}

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
    fn project_self_component_carries_name_version_license() {
        let (_d, ctx) = temp_ctx(&[(
            "meson.build",
            "project('tomlplusplus', 'cpp',\n  version: '3.4.0',\n  license: 'MIT',\n  default_options: ['cpp_std=c++17'])\n",
        )]);
        let out = MesonCataloger.catalog(&ctx).unwrap();
        let self_comp = out
            .iter()
            .find(|c| c.matching_method == "meson_project")
            .expect("project() self-component must be emitted");
        assert_eq!(self_comp.name, "tomlplusplus");
        assert_eq!(self_comp.version.as_deref(), Some("3.4.0"));
        assert_eq!(self_comp.component_type, "source");
        assert_eq!(self_comp.license.as_deref(), Some("MIT"));
        assert_eq!(
            self_comp.purl.as_deref(),
            Some("pkg:generic/tomlplusplus@3.4.0")
        );
    }

    #[test]
    fn dependency_calls_become_components() {
        let (_d, ctx) = temp_ctx(&[(
            "meson.build",
            "project('app', 'c', version: '1.0')\n\
             zdep = dependency('zlib', version: '1.3.1')\n\
             fdep = dependency('fmt')\n",
        )]);
        let out = MesonCataloger.catalog(&ctx).unwrap();
        let zlib = out
            .iter()
            .find(|c| c.name == "zlib" && c.matching_method == "meson_dependency")
            .expect("zlib dependency present");
        assert_eq!(zlib.version.as_deref(), Some("1.3.1"));
        assert_eq!(zlib.purl.as_deref(), Some("pkg:generic/zlib@1.3.1"));
        let fmt = out
            .iter()
            .find(|c| c.name == "fmt" && c.matching_method == "meson_dependency")
            .expect("fmt dependency present");
        assert!(fmt.version.is_none(), "no version: → version-less");
    }

    #[test]
    fn subproject_does_not_match_project_call() {
        // `subproject('x')` must NOT be parsed as the project() identity.
        let (_d, ctx) = temp_ctx(&[(
            "meson.build",
            "project('real', 'cpp', version: '2.0.0')\nsubproject('vendored')\n",
        )]);
        let out = MesonCataloger.catalog(&ctx).unwrap();
        let projects: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "meson_project")
            .collect();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "real");
    }

    #[test]
    fn version_range_constraint_stays_versionless() {
        let (_d, ctx) = temp_ctx(&[(
            "meson.build",
            "project('app', 'c')\ndependency('glib-2.0', version: '>=2.50')\n",
        )]);
        let out = MesonCataloger.catalog(&ctx).unwrap();
        let glib = out.iter().find(|c| c.name == "glib-2.0").unwrap();
        assert!(glib.version.is_none(), "a >= constraint is not a version");
        assert!(glib.purl.is_none());
    }

    #[test]
    fn wrap_file_yields_subproject_component_with_directory_version() {
        let (_d, ctx) = temp_ctx(&[(
            "subprojects/zlib.wrap",
            "[wrap-file]\ndirectory = zlib-1.3.1\nsource_filename = zlib-1.3.1.tar.gz\n",
        )]);
        let out = MesonCataloger.catalog(&ctx).unwrap();
        let zlib = out
            .iter()
            .find(|c| c.matching_method == "meson_wrap" && c.name == "zlib")
            .expect("wrap component present");
        assert_eq!(zlib.version.as_deref(), Some("1.3.1"));
    }

    #[test]
    fn detect_true_for_meson_build_and_wrap() {
        let with_build = CatalogContext::new("/r".into(), vec![PathBuf::from("/r/meson.build")]);
        assert!(MesonCataloger.detect(&with_build));
        let with_wrap =
            CatalogContext::new("/r".into(), vec![PathBuf::from("/r/subprojects/zlib.wrap")]);
        assert!(MesonCataloger.detect(&with_wrap));
        let without = CatalogContext::new("/r".into(), vec![PathBuf::from("/r/Cargo.toml")]);
        assert!(!MesonCataloger.detect(&without));
    }
}
