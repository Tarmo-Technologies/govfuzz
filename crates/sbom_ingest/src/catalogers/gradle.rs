// SPDX-License-Identifier: Apache-2.0

//! Gradle (JVM) ecosystem cataloger.
//!
//! **Declared**: `build.gradle` / `build.gradle.kts` — Groovy/Kotlin code
//! (string-extract only; no AST execution).  Versions are often symbolic
//! (`libs.*` references, `+`, ranges) → many will remain unpinned (Declared
//! without a PURL `@version`).
//!
//! **Resolved** (no hashes): `gradle.lockfile` (project root), optionally
//! `buildscript-gradle.lockfile`, and legacy per-config files under
//! `gradle/dependency-locks/*.lockfile`.  Each line is `group:name:version=configs`
//! — split on the **first `=`** (RHS is the config list, NOT a hash).  `empty=`
//! lines and `#` comments are skipped.  No hashes exist in any lockfile variant.
//!
//! # Version catalog
//! When `gradle/libs.versions.toml` is present, symbolic versions (`libs.x.y`)
//! declared in `build.gradle(.kts)` are resolved via the `[versions]` and
//! `[libraries]` tables.
//!
//! # PURL
//! `pkg:maven/<group>/<name>@<version>` — there is no `pkg:gradle` PURL type;
//! Gradle artifacts are Maven-compatible coordinates.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::Component;
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct GradleCataloger;

impl Cataloger for GradleCataloger {
    fn ecosystem(&self) -> &str {
        "gradle"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("build.gradle").next().is_some()
            || ctx.files_named("build.gradle.kts").next().is_some()
            || ctx.files_named("gradle.lockfile").next().is_some()
            || ctx
                .files_named("buildscript-gradle.lockfile")
                .next()
                .is_some()
            || ctx.files_ending_with(".lockfile").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();

        // Build name → LockPin index from lockfiles.
        let mut lock_index: HashMap<String, LockPin> = HashMap::new();

        for lock_path in ctx.files_named("gradle.lockfile") {
            let rel = relative_path(&ctx.root, lock_path);
            for pin in parse_gradle_lockfile(lock_path, &rel)? {
                let key = format!("{}:{}", pin.group, pin.name);
                lock_index.entry(key.clone()).or_insert_with(|| pin.clone());
                out.push(lock_pin_to_component(&pin, "gradle_lockfile"));
            }
        }

        for lock_path in ctx.files_named("buildscript-gradle.lockfile") {
            let rel = relative_path(&ctx.root, lock_path);
            for pin in parse_gradle_lockfile(lock_path, &rel)? {
                let key = format!("{}:{}", pin.group, pin.name);
                lock_index.entry(key.clone()).or_insert_with(|| pin.clone());
                out.push(lock_pin_to_component(&pin, "buildscript_lockfile"));
            }
        }

        // Legacy per-config lock files under gradle/dependency-locks/*.lockfile.
        for lock_path in ctx.files_ending_with(".lockfile") {
            let fname = lock_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // Skip the two top-level files already handled above.
            if fname == "gradle.lockfile" || fname == "buildscript-gradle.lockfile" {
                continue;
            }
            let rel = relative_path(&ctx.root, lock_path);
            for pin in parse_legacy_lockfile(lock_path, &rel)? {
                let key = format!("{}:{}", pin.group, pin.name);
                lock_index.entry(key.clone()).or_insert_with(|| pin.clone());
                out.push(lock_pin_to_component(&pin, "gradle_dep_lock"));
            }
        }

        // Load version catalog if present.
        let version_catalog = load_version_catalog(ctx);

        // Declared lane: build.gradle / build.gradle.kts.
        for build_path in ctx
            .files_named("build.gradle")
            .chain(ctx.files_named("build.gradle.kts"))
        {
            let rel = relative_path(&ctx.root, build_path);
            for dep in parse_build_gradle(build_path, &rel)? {
                out.push(declared_component(dep, &lock_index, &version_catalog));
            }
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Internal data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LockPin {
    group: String,
    name: String,
    version: String,
    relative: String,
}

#[derive(Debug, Clone)]
struct DeclaredDep {
    group: String,
    name: String,
    /// Raw version string from build.gradle — may be symbolic/range.
    version_raw: Option<String>,
    relative: String,
}

fn lock_pin_to_component(pin: &LockPin, method: &str) -> Component {
    let purl_val = purl::maven(&pin.group, &pin.name, &pin.version);
    let source = format!("{}:{}:{}", pin.relative, pin.group, pin.name);
    Component {
        component_ref: String::new(),
        name: pin.name.clone(),
        version: Some(pin.version.clone()),
        ecosystem: "gradle".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(purl_val),
        cpe: None,
        sha256: None,
        hashes: Vec::new(), // No hashes in Gradle lockfiles.
        identity_confidence: "high".to_owned(),
        matching_method: method.to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Resolved, source)],
        runtime_harnesses: Vec::new(),
    }
}

fn declared_component(
    dep: DeclaredDep,
    lock_index: &HashMap<String, LockPin>,
    version_catalog: &VersionCatalog,
) -> Component {
    let source = format!("{}:{}:{}", dep.relative, dep.group, dep.name);
    let key = format!("{}:{}", dep.group, dep.name);

    // Resolve version: lockfile pin > catalog resolution > raw (if exact) > None.
    let (purl_val, resolved_version) = if let Some(pin) = lock_index.get(&key) {
        (
            Some(purl::maven(&dep.group, &dep.name, &pin.version)),
            Some(pin.version.clone()),
        )
    } else if let Some(raw) = &dep.version_raw {
        // Try to resolve symbolic version from catalog.
        let resolved = resolve_catalog_version(raw, version_catalog);
        let v = resolved.as_deref().or(Some(raw.as_str()));
        match v {
            Some(ver) if is_exact_version(ver) => (
                Some(purl::maven(&dep.group, &dep.name, ver)),
                Some(ver.to_owned()),
            ),
            _ => (None, v.map(str::to_owned)),
        }
    } else {
        (None, None)
    };

    Component {
        component_ref: String::new(),
        name: dep.name,
        version: resolved_version,
        ecosystem: "gradle".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "medium".to_owned(),
        matching_method: "build_gradle".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, source)],
        runtime_harnesses: Vec::new(),
    }
}

/// True if a version string looks like an exact pin (no `+`, `[`, `(`, `*`, wildcards).
fn is_exact_version(v: &str) -> bool {
    !v.contains('+')
        && !v.contains('[')
        && !v.contains('(')
        && !v.contains('*')
        && !v.contains("latest")
        && !v.is_empty()
}

// ---------------------------------------------------------------------------
// gradle.lockfile parser (standard format)
// ---------------------------------------------------------------------------

fn parse_gradle_lockfile(path: &Path, relative: &str) -> Result<Vec<LockPin>, CatalogError> {
    let source = read_to_string(path)?;
    Ok(parse_lockfile_lines(&source, relative))
}

fn parse_lockfile_lines(source: &str, relative: &str) -> Vec<LockPin> {
    let mut out = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        // Skip comments and empty lines.
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        // Split on FIRST `=` — RHS is configs, NOT a hash.
        let (lhs, _rhs) = match line.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        // Skip `empty=<configs>` lines.
        if lhs == "empty" {
            continue;
        }
        // LHS is `group:name:version`.
        let parts: Vec<&str> = lhs.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let group = parts[0].trim().to_owned();
        let name = parts[1].trim().to_owned();
        let version = parts[2].trim().to_owned();
        if group.is_empty() || name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(LockPin {
            group,
            name,
            version,
            relative: relative.to_owned(),
        });
    }
    // Dedup by group:name (keep first version seen).
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(format!("{}:{}", p.group, p.name)));
    out
}

// ---------------------------------------------------------------------------
// Legacy per-config lockfile parser (bare `group:name:version` lines)
// ---------------------------------------------------------------------------

fn parse_legacy_lockfile(path: &Path, relative: &str) -> Result<Vec<LockPin>, CatalogError> {
    let source = read_to_string(path)?;
    let mut out = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        // May or may not have `=config` suffix — handle both.
        let lhs = line.split_once('=').map(|(l, _)| l).unwrap_or(line);
        let parts: Vec<&str> = lhs.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let group = parts[0].trim().to_owned();
        let name = parts[1].trim().to_owned();
        let version = parts[2].trim().to_owned();
        if group.is_empty() || name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(LockPin {
            group,
            name,
            version,
            relative: relative.to_owned(),
        });
    }
    // Dedup by group:name:version (the same coordinate recurs across configs).
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(format!("{}:{}:{}", p.group, p.name, p.version)));
    Ok(out)
}

// ---------------------------------------------------------------------------
// build.gradle / build.gradle.kts parser (Declared lane)
// ---------------------------------------------------------------------------

/// String-extract dependencies from Groovy/Kotlin Gradle build files.
/// We never exec the file — only static string patterns are recognized:
/// - String GAV form: `config 'group:name:version'` or `config "g:n:v"`
/// - Map form: `group: 'g', name: 'n', version: 'v'`
fn parse_build_gradle(path: &Path, relative: &str) -> Result<Vec<DeclaredDep>, CatalogError> {
    let source = read_to_string(path)?;
    let mut out = Vec::new();

    for line in source.lines() {
        let trimmed = line.trim();
        // Skip comments.
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue;
        }

        // Try string GAV form: some_config 'group:name:version' or (...)
        if let Some(dep) = try_parse_string_gav(trimmed, relative) {
            out.push(dep);
            continue;
        }

        // Try map form: group: 'g', name: 'n', version: 'v'
        if let Some(dep) = try_parse_map_form(trimmed, relative) {
            out.push(dep);
        }
    }

    // Dedup by group:name.
    let mut seen = std::collections::HashSet::new();
    out.retain(|d| seen.insert(format!("{}:{}", d.group, d.name)));

    Ok(out)
}

/// Recognized Gradle dependency-configuration keywords. A quoted GAV that is NOT
/// preceded by one of these is only accepted if it is an unambiguous 3-part
/// `group:name:version` with a plausible version — otherwise it is a false
/// positive (an arbitrary `"a:b"` string in unrelated Groovy/Kotlin).
const DEP_CONFIG_KEYWORDS: &[&str] = &[
    "implementation",
    "api",
    "compileOnly",
    "compileOnlyApi",
    "runtimeOnly",
    "testImplementation",
    "testCompileOnly",
    "testRuntimeOnly",
    "androidTestImplementation",
    "debugImplementation",
    "releaseImplementation",
    "annotationProcessor",
    "kapt",
    "ksp",
    "classpath",
    "compile",
    "testCompile",
    "providedCompile",
    "providedRuntime",
];

/// Does `line` begin (after leading whitespace) with a dependency-config keyword
/// applied to the coordinate (`keyword '...'`, `keyword("...")`, `keyword(...`)?
fn has_dep_config_keyword(line: &str) -> bool {
    let trimmed = line.trim_start();
    DEP_CONFIG_KEYWORDS.iter().any(|kw| {
        trimmed.strip_prefix(kw).is_some_and(|rest| {
            // The keyword must be a token: followed by space, `(`, or quote.
            rest.starts_with([' ', '(', '\'', '"'])
        })
    })
}

/// A plausible Maven version: starts with a digit (e.g. `1.2.3`, `33.0.0-jre`).
/// Excludes nonsense like a single letter so bare `a:b:c` is rejected.
fn is_plausible_version(v: &str) -> bool {
    v.chars().next().is_some_and(|c| c.is_ascii_digit())
}

/// Try to parse: `<config> 'group:name:version'` or `<config> "group:name:version"`.
fn try_parse_string_gav(line: &str, relative: &str) -> Option<DeclaredDep> {
    // Find a quoted string containing `:`-separated GAV.
    let quote_char = if line.contains('\'') {
        '\''
    } else if line.contains('"') {
        '"'
    } else {
        return None;
    };

    // Extract content between first pair of matching quotes.
    let start = line.find(quote_char)?;
    let after = &line[start + 1..];
    let end = after.find(quote_char)?;
    let quoted = &after[..end];

    // Must look like group:name or group:name:version.
    let parts: Vec<&str> = quoted.splitn(3, ':').collect();
    if parts.len() < 2 {
        return None;
    }
    let group = parts[0].trim().to_owned();
    let name = parts[1].trim().to_owned();
    if group.is_empty() || name.is_empty() {
        return None;
    }
    let version_raw = parts.get(2).map(|v| v.trim().to_owned());

    // Gate against false positives: accept only when a dependency-config keyword
    // precedes the coordinate, OR it is an unambiguous 3-part g:n:v with a
    // plausible (digit-led) version. An arbitrary `"a:b:c"` in unrelated code
    // (no keyword, implausible version) is rejected.
    let has_keyword = has_dep_config_keyword(line);
    let plausible_gnv = version_raw.as_deref().is_some_and(is_plausible_version);
    if !has_keyword && !plausible_gnv {
        return None;
    }

    Some(DeclaredDep {
        group,
        name,
        version_raw,
        relative: relative.to_owned(),
    })
}

/// Try to parse map form: `... group: 'g', name: 'n', version: 'v'`.
fn try_parse_map_form(line: &str, relative: &str) -> Option<DeclaredDep> {
    if !line.contains("group:") && !line.contains("group :") {
        return None;
    }
    let group = extract_map_value(line, "group")?;
    let name = extract_map_value(line, "name")?;
    if group.is_empty() || name.is_empty() {
        return None;
    }
    let version_raw = extract_map_value(line, "version");
    Some(DeclaredDep {
        group,
        name,
        version_raw,
        relative: relative.to_owned(),
    })
}

/// Extract the value of `key: 'val'` or `key: "val"` from a Gradle map dep line.
fn extract_map_value(line: &str, key: &str) -> Option<String> {
    // Find `key:` (with optional space before the colon).
    let pattern = format!("{key}:");
    let pos = line.find(&pattern)?;
    let after = &line[pos + pattern.len()..];
    // Skip whitespace.
    let after = after.trim_start();
    // Expect a quoted string.
    let quote = if after.starts_with('\'') {
        '\''
    } else if after.starts_with('"') {
        '"'
    } else {
        return None;
    };
    let inner = &after[1..];
    let end = inner.find(quote)?;
    Some(inner[..end].to_owned())
}

// ---------------------------------------------------------------------------
// Version catalog (gradle/libs.versions.toml)
// ---------------------------------------------------------------------------

struct VersionCatalog {
    /// `alias → version string` from [versions]
    versions: HashMap<String, String>,
    /// `alias → (group, name, version_ref_or_literal)` from [libraries]
    libraries: HashMap<String, (String, String, String)>,
}

impl VersionCatalog {
    fn empty() -> Self {
        VersionCatalog {
            versions: HashMap::new(),
            libraries: HashMap::new(),
        }
    }
}

fn load_version_catalog(ctx: &CatalogContext) -> VersionCatalog {
    let catalog_path = ctx
        .files
        .iter()
        .find(|p| p.file_name().and_then(|n| n.to_str()) == Some("libs.versions.toml"));

    let Some(path) = catalog_path else {
        return VersionCatalog::empty();
    };

    let Ok(source) = fs::read_to_string(path) else {
        return VersionCatalog::empty();
    };

    parse_version_catalog(&source)
}

fn parse_version_catalog(source: &str) -> VersionCatalog {
    let mut catalog = VersionCatalog::empty();
    let mut current_section = "";

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if trimmed == "[versions]" {
            current_section = "versions";
            continue;
        }
        if trimmed == "[libraries]" {
            current_section = "libraries";
            continue;
        }
        if trimmed.starts_with('[') {
            current_section = "";
            continue;
        }

        match current_section {
            "versions" => {
                // alias = "1.2.3"
                if let Some((key, val)) = trimmed.split_once('=') {
                    let key = key.trim().to_owned();
                    let val = val.trim().trim_matches('"').trim_matches('\'').to_owned();
                    catalog.versions.insert(key, val);
                }
            }
            "libraries" => {
                // alias = { group = "g", name = "n", version.ref = "alias" }
                // or alias = { group = "g", name = "n", version = "x" }
                if let Some((key, val)) = trimmed.split_once('=') {
                    let key = key.trim().to_owned();
                    let val = val.trim();
                    if val.contains('{') {
                        let group = extract_toml_inline_field(val, "group").unwrap_or_default();
                        let name = extract_toml_inline_field(val, "name").unwrap_or_default();
                        // version.ref or version
                        let ver_ref = extract_toml_inline_field(val, "version.ref")
                            .or_else(|| extract_toml_inline_field(val, "version"))
                            .unwrap_or_default();
                        if !group.is_empty() && !name.is_empty() {
                            catalog.libraries.insert(key, (group, name, ver_ref));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    catalog
}

fn extract_toml_inline_field(s: &str, key: &str) -> Option<String> {
    // Find `key = "val"` or `key = 'val'` inside an inline table.
    let pattern = format!("{key} = ");
    let pos = s.find(&pattern)?;
    let after = &s[pos + pattern.len()..];
    let after = after.trim_start();
    let quote = if after.starts_with('"') {
        '"'
    } else if after.starts_with('\'') {
        '\''
    } else {
        return None;
    };
    let inner = &after[1..];
    let end = inner.find(quote)?;
    Some(inner[..end].to_owned())
}

/// Attempt to resolve a symbolic version reference (e.g. `libs.commons.lang3`)
/// using the version catalog.  Returns `Some(version)` when resolvable, `None`
/// otherwise.
fn resolve_catalog_version(raw: &str, catalog: &VersionCatalog) -> Option<String> {
    // Direct hit in [versions].
    if let Some(v) = catalog.versions.get(raw) {
        return Some(v.clone());
    }
    // A `libs.x.y` reference maps to a library alias `x-y` or `x.y`.
    if raw.starts_with("libs.") {
        let alias_dot = raw.strip_prefix("libs.").unwrap_or(raw);
        let alias_dash = alias_dot.replace('.', "-");
        for alias in &[alias_dot, alias_dash.as_str()] {
            if let Some((_, _, ver_ref)) = catalog.libraries.get(*alias) {
                if !ver_ref.is_empty() {
                    // ver_ref may be a version alias or a literal.
                    if let Some(v) = catalog.versions.get(ver_ref) {
                        return Some(v.clone());
                    }
                    return Some(ver_ref.clone());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_to_string(path: &Path) -> Result<String, CatalogError> {
    fs::read_to_string(path).map_err(|source| CatalogError::Io {
        path: path.to_path_buf(),
        source,
    })
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
    use crate::evidence::{top_rung, EvidenceKind};
    use std::path::PathBuf;

    fn fixture_ctx(name: &str) -> CatalogContext {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let files = collect_files(&root);
        CatalogContext::new(root, files)
    }

    fn collect_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        collect_recursive(dir, &mut files);
        files.sort();
        files
    }

    fn collect_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_recursive(&path, out);
            } else {
                out.push(path);
            }
        }
    }

    // -----------------------------------------------------------------------
    // lockfile parsing
    // -----------------------------------------------------------------------

    #[test]
    fn lockfile_yields_resolved_components() {
        let ctx = fixture_ctx("gradle");
        let out = GradleCataloger.catalog(&ctx).unwrap();
        let lock_comps: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "gradle_lockfile")
            .collect();
        assert!(!lock_comps.is_empty(), "lockfile must yield components");
        let names: Vec<_> = lock_comps.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"jackson-databind"));
        assert!(names.contains(&"jackson-core"));
        assert!(names.contains(&"junit"));
    }

    #[test]
    fn lockfile_empty_line_skipped() {
        let ctx = fixture_ctx("gradle");
        let out = GradleCataloger.catalog(&ctx).unwrap();
        // `empty=annotationProcessor` must not emit a component named "empty".
        assert!(
            out.iter().all(|c| c.name != "empty"),
            "empty= lines must not emit components"
        );
    }

    #[test]
    fn lockfile_purl_uses_maven_type() {
        let ctx = fixture_ctx("gradle");
        let out = GradleCataloger.catalog(&ctx).unwrap();
        let jackson = out
            .iter()
            .find(|c| c.name == "jackson-databind" && c.matching_method == "gradle_lockfile")
            .unwrap();
        assert_eq!(jackson.version.as_deref(), Some("2.17.0"));
        assert_eq!(
            jackson.purl.as_deref(),
            Some("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0")
        );
    }

    #[test]
    fn lockfile_evidence_is_resolved() {
        let ctx = fixture_ctx("gradle");
        let out = GradleCataloger.catalog(&ctx).unwrap();
        let jackson = out
            .iter()
            .find(|c| c.name == "jackson-databind" && c.matching_method == "gradle_lockfile")
            .unwrap();
        assert_eq!(top_rung(&jackson.evidence), Some(EvidenceKind::Resolved));
    }

    #[test]
    fn no_hashes_in_lockfile_components() {
        let ctx = fixture_ctx("gradle");
        let out = GradleCataloger.catalog(&ctx).unwrap();
        for c in out
            .iter()
            .filter(|c| c.matching_method == "gradle_lockfile")
        {
            assert!(c.hashes.is_empty(), "Gradle lockfiles carry no hashes");
        }
    }

    // -----------------------------------------------------------------------
    // build.gradle declared lane
    // -----------------------------------------------------------------------

    #[test]
    fn build_gradle_yields_declared_components() {
        let ctx = fixture_ctx("gradle");
        let out = GradleCataloger.catalog(&ctx).unwrap();
        let declared: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "build_gradle")
            .collect();
        assert!(
            !declared.is_empty(),
            "build.gradle must yield declared components"
        );
        let names: Vec<_> = declared.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"jackson-databind"),
            "jackson-databind must be declared"
        );
        assert!(
            names.contains(&"spring-core"),
            "spring-core must be declared"
        );
        assert!(
            names.contains(&"guava"),
            "guava (map form) must be declared"
        );
    }

    #[test]
    fn build_gradle_evidence_is_declared() {
        let ctx = fixture_ctx("gradle");
        let out = GradleCataloger.catalog(&ctx).unwrap();
        let declared: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "build_gradle")
            .collect();
        for c in &declared {
            assert_eq!(
                top_rung(&c.evidence),
                Some(EvidenceKind::Declared),
                "{} must be Declared",
                c.name
            );
        }
    }

    // -----------------------------------------------------------------------
    // lockfile + declared merge
    // -----------------------------------------------------------------------

    #[test]
    fn lockfile_and_declared_merge_to_single_component() {
        let ctx = fixture_ctx("gradle");
        let raw = GradleCataloger.catalog(&ctx).unwrap();
        let merged = crate::merge_by_identity(raw);
        let jackson: Vec<_> = merged
            .iter()
            .filter(|c| {
                c.purl.as_deref()
                    == Some("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0")
            })
            .collect();
        assert_eq!(
            jackson.len(),
            1,
            "jackson-databind must collapse to 1 component"
        );
        assert!(jackson[0]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Declared));
        assert!(jackson[0]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Resolved));
    }

    // -----------------------------------------------------------------------
    // lockfile line parser unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn lockfile_line_parse_basic() {
        let lines = "com.example:foo:1.0.0=compileClasspath,runtimeClasspath\n\
             empty=annotationProcessor\n\
             # comment\n\
             org.test:bar:2.0.0=testRuntime\n";
        let pins = parse_lockfile_lines(lines, "gradle.lockfile");
        assert_eq!(pins.len(), 2);
        assert_eq!(pins[0].group, "com.example");
        assert_eq!(pins[0].name, "foo");
        assert_eq!(pins[0].version, "1.0.0");
        assert_eq!(pins[1].group, "org.test");
        assert_eq!(pins[1].name, "bar");
        assert_eq!(pins[1].version, "2.0.0");
    }

    // -----------------------------------------------------------------------
    // version catalog resolution
    // -----------------------------------------------------------------------

    #[test]
    fn version_catalog_resolves_library_alias() {
        let toml = r#"
[versions]
commons-lang3 = "3.14.0"

[libraries]
commons-lang3 = { group = "org.apache.commons", name = "commons-lang3", version.ref = "commons-lang3" }
"#;
        let catalog = parse_version_catalog(toml);
        let resolved = resolve_catalog_version("libs.commons.lang3", &catalog);
        assert_eq!(resolved, Some("3.14.0".to_owned()));
    }

    // -----------------------------------------------------------------------
    // detect
    // -----------------------------------------------------------------------

    #[test]
    fn detect_true_for_build_gradle() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/build.gradle".into()]);
        assert!(GradleCataloger.detect(&ctx));
    }

    #[test]
    fn detect_true_for_gradle_lockfile() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/gradle.lockfile".into()]);
        assert!(GradleCataloger.detect(&ctx));
    }

    #[test]
    fn detect_false_without_gradle_files() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/Cargo.toml".into()]);
        assert!(!GradleCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // string GAV parser helper
    // -----------------------------------------------------------------------

    #[test]
    fn try_parse_string_gav_standard() {
        let dep = try_parse_string_gav(
            "implementation 'com.google.guava:guava:33.0.0-jre'",
            "build.gradle",
        )
        .unwrap();
        assert_eq!(dep.group, "com.google.guava");
        assert_eq!(dep.name, "guava");
        assert_eq!(dep.version_raw.as_deref(), Some("33.0.0-jre"));
    }

    // -----------------------------------------------------------------------
    // false-positive gating: arbitrary `a:b` strings must not become components
    // -----------------------------------------------------------------------

    #[test]
    fn non_dependency_colon_string_is_not_emitted() {
        // A quoted `"a:b:c"` in arbitrary Groovy (no dependency-config keyword,
        // implausible 1-char "version") must NOT yield a phantom Maven component.
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("build.gradle");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(b"task foo {\n    description = 'a:b:c'\n    systemProperty 'x:y', 'z'\n}\n")
            .unwrap();
        let ctx = CatalogContext::new(dir.path().to_path_buf(), vec![p]);
        let out = GradleCataloger.catalog(&ctx).unwrap();
        let declared: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "build_gradle")
            .collect();
        assert!(
            declared.is_empty(),
            "no dependency keyword + implausible coords → no components: {declared:?}"
        );
    }

    #[test]
    fn real_implementation_gav_is_emitted() {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("build.gradle");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(b"dependencies {\n    implementation 'g.h:n:1.2.3'\n}\n")
            .unwrap();
        let ctx = CatalogContext::new(dir.path().to_path_buf(), vec![p]);
        let out = GradleCataloger.catalog(&ctx).unwrap();
        let n = out
            .iter()
            .find(|c| c.matching_method == "build_gradle" && c.name == "n")
            .expect("real implementation dep must be emitted");
        assert_eq!(n.version.as_deref(), Some("1.2.3"));
        assert_eq!(n.purl.as_deref(), Some("pkg:maven/g.h/n@1.2.3"));
    }

    #[test]
    fn legacy_lockfile_dedups_by_gnv() {
        let lines = "com.example:foo:1.0.0=compileClasspath\n\
                     com.example:foo:1.0.0=runtimeClasspath\n";
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("dep.lockfile");
        std::fs::write(&p, lines).unwrap();
        let pins = parse_legacy_lockfile(&p, "dep.lockfile").unwrap();
        assert_eq!(
            pins.len(),
            1,
            "legacy lockfile must dedup by group:name:version"
        );
    }

    #[test]
    fn try_parse_map_form_standard() {
        let dep = try_parse_map_form(
            "implementation group: 'com.google.guava', name: 'guava', version: '33.0.0-jre'",
            "build.gradle",
        )
        .unwrap();
        assert_eq!(dep.group, "com.google.guava");
        assert_eq!(dep.name, "guava");
        assert_eq!(dep.version_raw.as_deref(), Some("33.0.0-jre"));
    }
}
