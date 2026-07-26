// SPDX-License-Identifier: Apache-2.0

//! Ruby (RubyGems / Bundler) ecosystem cataloger.
//!
//! **Declared**: `Gemfile` (`gem "name", "constraint"` lines).
//! **Resolved**: `Gemfile.lock` (indentation-significant plain text, NOT YAML).
//!
//! # Gemfile.lock parsing rules (per Syft + spec)
//! - Lines indented exactly **4 spaces** inside a `GEM` → `specs:` block are
//!   resolved specs: `    name (version)` or `    name (version-platform)`.
//! - Lines indented **6 spaces** are transitive dependency edges — NOT components.
//! - The `DEPENDENCIES` section holds direct/top-level markers (constraints, not
//!   pins); we use it only to annotate direct vs transitive.
//! - **Do NOT feed Gemfile.lock to a YAML parser.** It is NOT valid YAML.
//!
//! # Hash
//! None by default. Bundler 2.5+ may append a `CHECKSUMS` section:
//! `    name (version) sha256=<64-hex>` → `HashRef{alg:"SHA-256", ...}`.
//!
//! # PURL
//! `pkg:gem/<name>@<version>`. Platform suffix like `-x86_64-linux` goes into
//! `?platform=<plat>` qualifier; `ruby` (default) is omitted.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::{Component, HashRef};
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

pub struct RubyCataloger;

impl Cataloger for RubyCataloger {
    fn ecosystem(&self) -> &str {
        "gem"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("Gemfile").next().is_some()
            || ctx.files_named("Gemfile.lock").next().is_some()
            || ctx.files_ending_with(".gemspec").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();

        // Build name → LockSpec index from lockfile(s).
        let mut lock_index: HashMap<String, LockSpec> = HashMap::new();

        for path in ctx.files_named("Gemfile.lock") {
            let rel = relative_path(&ctx.root, path);
            for spec in parse_gemfile_lock(path, &rel)? {
                lock_index
                    .entry(spec.name.clone())
                    .or_insert_with(|| spec.clone());
                out.push(lock_spec_to_component(spec));
            }
        }

        // Gemfile: Declared lane.
        for path in ctx.files_named("Gemfile") {
            let rel = relative_path(&ctx.root, path);
            for dep in parse_gemfile(path, &rel)? {
                out.push(declared_component(dep, &lock_index));
            }
        }

        // *.gemspec: Declared lane (regex-extract only; never eval).
        for path in ctx.files_ending_with(".gemspec") {
            let rel = relative_path(&ctx.root, path);
            for dep in parse_gemspec(path, &rel)? {
                out.push(declared_component(dep, &lock_index));
            }
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Internal data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LockSpec {
    name: String,
    version: String,
    platform: Option<String>,
    sha256: Option<String>,
    relative: String,
}

#[derive(Debug, Clone)]
struct DeclaredGem {
    name: String,
    relative: String,
}

fn lock_spec_to_component(spec: LockSpec) -> Component {
    let purl_val = gem_purl(&spec.name, &spec.version, spec.platform.as_deref());
    let hashes = spec
        .sha256
        .as_deref()
        .map(|hex| {
            vec![HashRef {
                alg: "SHA-256".to_owned(),
                value_hex: hex.to_owned(),
            }]
        })
        .unwrap_or_default();
    let source = format!("{}:{} ({})", spec.relative, spec.name, spec.version);
    Component {
        component_ref: String::new(),
        name: spec.name,
        version: Some(spec.version),
        ecosystem: "gem".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(purl_val),
        cpe: None,
        sha256: spec.sha256.clone(),
        hashes,
        identity_confidence: "high".to_owned(),
        matching_method: "gemfile_lock".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Resolved, source)],
        runtime_harnesses: Vec::new(),
    }
}

fn declared_component(dep: DeclaredGem, lock_index: &HashMap<String, LockSpec>) -> Component {
    let source = format!("{}:{}", dep.relative, dep.name);
    let purl_val = if let Some(spec) = lock_index.get(&dep.name) {
        Some(gem_purl(&dep.name, &spec.version, spec.platform.as_deref()))
    } else {
        None
    };
    Component {
        component_ref: String::new(),
        name: dep.name,
        version: None,
        ecosystem: "gem".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "medium".to_owned(),
        matching_method: "gemfile".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, source)],
        runtime_harnesses: Vec::new(),
    }
}

/// Build a `pkg:gem` PURL with an optional platform qualifier.
/// Platform `ruby` (default) is omitted; other platforms become `?platform=`.
fn gem_purl(name: &str, version: &str, platform: Option<&str>) -> String {
    let base = purl::gem(name, version);
    match platform {
        Some(p) if p != "ruby" => format!("{base}?platform={p}"),
        _ => base,
    }
}

// ---------------------------------------------------------------------------
// Gemfile.lock parser
// ---------------------------------------------------------------------------

/// State machine for the Gemfile.lock section tracker.
#[derive(Debug, Clone, Copy, PartialEq)]
enum LockSection {
    Other,
    GemSpecs,
    Dependencies,
    Checksums,
}

fn parse_gemfile_lock(path: &Path, relative: &str) -> Result<Vec<LockSpec>, CatalogError> {
    let source = read_to_string(path)?;

    let mut section = LockSection::Other;
    let mut in_specs = false;
    let mut specs: Vec<LockSpec> = Vec::new();
    // name → sha256 from CHECKSUMS.
    let mut checksums: HashMap<String, String> = HashMap::new();
    // Names listed in DEPENDENCIES section.
    let mut direct_names: HashSet<String> = HashSet::new();

    for line in source.lines() {
        // Section boundary: line with no leading whitespace (or end of specs).
        if !line.starts_with(' ') && !line.starts_with('\t') {
            let trimmed = line.trim();
            match trimmed {
                "GEM" => {
                    section = LockSection::Other; // will wait for `specs:`
                    in_specs = false;
                }
                "DEPENDENCIES" => {
                    section = LockSection::Dependencies;
                    in_specs = false;
                }
                "CHECKSUMS" => {
                    section = LockSection::Checksums;
                    in_specs = false;
                }
                _ => {
                    section = LockSection::Other;
                    in_specs = false;
                }
            }
            continue;
        }

        let trimmed = line.trim();

        match section {
            LockSection::Other => {
                // Inside GEM block, wait for `specs:`.
                if trimmed == "specs:" {
                    section = LockSection::GemSpecs;
                    in_specs = true;
                }
            }

            LockSection::GemSpecs => {
                if !in_specs {
                    continue;
                }
                // Count leading spaces.
                let leading = count_leading_spaces(line);
                if leading == 4 {
                    // Resolved spec line: `    name (version)` or `    name (version-platform)`.
                    if let Some(spec) = parse_spec_line(trimmed, relative) {
                        specs.push(spec);
                    }
                }
                // leading == 6 → transitive edge; skip.
                // leading < 4 → end of specs block handled by section change.
            }

            LockSection::Dependencies => {
                // `  name (constraint)` — record name only.
                if let Some(name) = trimmed.split_whitespace().next() {
                    direct_names.insert(name.to_owned());
                }
            }

            LockSection::Checksums => {
                // `    name (version) sha256=<hex>` — 4-space lines only.
                if count_leading_spaces(line) == 4 {
                    parse_checksum_line(trimmed, &mut checksums);
                }
            }
        }
    }

    // Attach checksums.
    for spec in &mut specs {
        if let Some(hex) = checksums.get(&spec.name) {
            spec.sha256 = Some(hex.clone());
        }
    }

    let _ = direct_names; // used for potential future scope annotation.

    Ok(specs)
}

/// Parse a 4-space GEM spec line: `name (version)` or `name (version-platform)`.
fn parse_spec_line(trimmed: &str, relative: &str) -> Option<LockSpec> {
    // Find the opening paren.
    let paren_open = trimmed.find('(')?;
    let paren_close = trimmed.find(')')?;
    if paren_close <= paren_open {
        return None;
    }

    let name = trimmed[..paren_open].trim().to_owned();
    let ver_platform = trimmed[paren_open + 1..paren_close].trim();

    if name.is_empty() || ver_platform.is_empty() {
        return None;
    }

    // Split platform suffix: `1.16.5-x86_64-linux` → version=`1.16.5`, platform=`x86_64-linux`.
    // Strategy: the version part is semver-ish (digits + dots), platform comes after the first `-`
    // that follows a digit character.
    let (version, platform) = split_version_platform(ver_platform);

    Some(LockSpec {
        name,
        version,
        platform,
        sha256: None,
        relative: relative.to_owned(),
    })
}

/// Split `version[-platform]` → (version, Option<platform>).
/// Examples: `1.16.5` → (`1.16.5`, None), `1.16.5-x86_64-linux` → (`1.16.5`, Some(`x86_64-linux`)).
fn split_version_platform(s: &str) -> (String, Option<String>) {
    // Walk through and find the first `-` that is NOT between digits (not part of semver pre-release).
    // Simpler heuristic: split at the first `-` that is followed by a non-digit.
    // Use char_indices so the index is a BYTE offset — slicing by char index would
    // panic mid-codepoint on a multibyte version string (untrusted input).
    let mut iter = s.char_indices().peekable();
    while let Some((byte_i, ch)) = iter.next() {
        if ch == '-' {
            // Check if the next char is a letter (platform identifier starts with a letter or arch).
            if let Some(&(_, next)) = iter.peek() {
                if next.is_ascii_alphabetic() {
                    let version = s[..byte_i].to_owned();
                    let platform = s[byte_i + ch.len_utf8()..].to_owned();
                    return (version, Some(platform));
                }
            }
        }
    }
    (s.to_owned(), None)
}

/// Parse a CHECKSUMS line: `name (version) sha256=<hex>`.
fn parse_checksum_line(trimmed: &str, checksums: &mut HashMap<String, String>) {
    // Format: `name (version) sha256=<64hex>`
    // Find the `sha256=` part.
    if let Some(pos) = trimmed.find("sha256=") {
        let hex = &trimmed[pos + "sha256=".len()..];
        let hex: String = hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() == 64 {
            // Extract name (before the first space).
            if let Some(name) = trimmed.split_whitespace().next() {
                checksums.insert(name.to_owned(), hex);
            }
        }
    }
}

fn count_leading_spaces(line: &str) -> usize {
    line.chars().take_while(|&c| c == ' ').count()
}

// ---------------------------------------------------------------------------
// Gemfile parser (Declared)
// ---------------------------------------------------------------------------

fn parse_gemfile(path: &Path, relative: &str) -> Result<Vec<DeclaredGem>, CatalogError> {
    let source = read_to_string(path)?;
    let mut out = Vec::new();

    for line in source.lines() {
        let trimmed = line.trim();
        // Skip comments and directives.
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("source ")
            || trimmed.starts_with("ruby ")
            || trimmed.starts_with("gemspec")
            || trimmed.starts_with("group ")
            || trimmed.starts_with("end")
            || trimmed.starts_with("git_source")
            || trimmed.starts_with("platforms")
            || trimmed.starts_with("platform")
        {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("gem ") {
            // gem "name", "constraint", ...
            // Extract first string argument.
            let rest = rest.trim();
            let name = extract_first_string(rest);
            if !name.is_empty() {
                out.push(DeclaredGem {
                    name,
                    relative: relative.to_owned(),
                });
            }
        }
    }

    Ok(out)
}

/// Extract the first quoted string from a Gemfile `gem` call argument list.
fn extract_first_string(s: &str) -> String {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('"') {
        inner.split('"').next().unwrap_or("").to_owned()
    } else if let Some(inner) = s.strip_prefix('\'') {
        inner.split('\'').next().unwrap_or("").to_owned()
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// *.gemspec parser (regex-style, never eval)
// ---------------------------------------------------------------------------

fn parse_gemspec(path: &Path, relative: &str) -> Result<Vec<DeclaredGem>, CatalogError> {
    let source = read_to_string(path)?;
    let mut out = Vec::new();

    for line in source.lines() {
        let trimmed = line.trim();
        // `add_dependency`, `add_runtime_dependency`, `add_development_dependency`
        // — with or without parentheses, on any receiver name. Requiring
        // `s.add_dependency(` missed the idiomatic Ruby form,
        // `s.add_dependency "erubi", "~> 1.13"`, which is what real gemspecs are
        // written in: tmuxinator reported ZERO dependencies.
        for method in &[
            "add_runtime_dependency",
            "add_development_dependency",
            "add_dependency",
        ] {
            let Some(at) = trimmed.find(method) else {
                continue;
            };
            // Must be a method call on something (`s.`, `spec.`, `gem.`), not a
            // word inside a comment or a string.
            if !trimmed[..at].ends_with('.') {
                continue;
            }
            let rest = trimmed[at + method.len()..].trim_start();
            let rest = rest.strip_prefix('(').unwrap_or(rest).trim_start();
            let name = extract_first_string(rest);
            if !name.is_empty() {
                out.push(DeclaredGem {
                    name,
                    relative: relative.to_owned(),
                });
            }
            break;
        }
    }

    Ok(out)
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
    #[test]
    fn a_gemspec_declares_dependencies_without_parentheses() {
        // The idiomatic Ruby form has no parentheses. Requiring them made
        // tmuxinator — whose Gemfile is just `gemspec` — report zero
        // dependencies, and every gemspec-driven project with it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tmuxinator.gemspec");
        std::fs::write(
            &path,
            "Gem::Specification.new do |s|\n\
             \x20 s.add_dependency \"erubi\", \"~> 1.13\"\n\
             \x20 s.add_dependency \"thor\", \"~> 1.4.0\"\n\
             \x20 s.add_development_dependency \"rspec\"\n\
             \x20 spec.add_runtime_dependency(\"paren-style\", \">= 1\")\n\
             \x20 # add_dependency \"in-a-comment\"\n\
             end\n",
        )
        .expect("write gemspec");

        let gems = parse_gemspec(&path, "tmuxinator.gemspec").expect("parse");
        let names: Vec<&str> = gems.iter().map(|g| g.name.as_str()).collect();
        assert!(names.contains(&"erubi"), "{names:?}");
        assert!(names.contains(&"thor"), "{names:?}");
        assert!(names.contains(&"rspec"), "{names:?}");
        assert!(names.contains(&"paren-style"), "{names:?}");
        assert!(!names.contains(&"in-a-comment"), "{names:?}");
    }

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
    // Gemfile.lock parsing
    // -----------------------------------------------------------------------

    #[test]
    fn gemfile_lock_yields_4space_specs_as_components() {
        let ctx = fixture_ctx("ruby");
        let out = RubyCataloger.catalog(&ctx).unwrap();
        let lock_comps: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "gemfile_lock")
            .collect();
        let names: Vec<_> = lock_comps.iter().map(|c| c.name.as_str()).collect();
        // All 4-space spec lines must be present.
        assert!(names.contains(&"nokogiri"));
        assert!(names.contains(&"mini_portile2"));
        assert!(names.contains(&"racc"));
        assert!(names.contains(&"rake"));
        assert!(names.contains(&"rspec"));
        assert!(names.contains(&"rspec-core"));
        assert!(names.contains(&"rspec-expectations"));
        assert!(names.contains(&"rspec-mocks"));
    }

    #[test]
    fn gemfile_lock_does_not_emit_6space_transitive_edges() {
        // 6-space lines like `      mini_portile2 (~> 2.8.2)` must NOT become components.
        // Those would appear as duplicate names — verify count is exactly 1 for mini_portile2.
        let ctx = fixture_ctx("ruby");
        let out = RubyCataloger.catalog(&ctx).unwrap();
        let minis: Vec<_> = out
            .iter()
            .filter(|c| c.name == "mini_portile2" && c.matching_method == "gemfile_lock")
            .collect();
        assert_eq!(
            minis.len(),
            1,
            "mini_portile2 must appear exactly once (not the 6-space edge)"
        );
    }

    #[test]
    fn gemfile_lock_nokogiri_version_and_purl() {
        let ctx = fixture_ctx("ruby");
        let out = RubyCataloger.catalog(&ctx).unwrap();
        let noko = out
            .iter()
            .find(|c| c.name == "nokogiri" && c.matching_method == "gemfile_lock")
            .unwrap();
        assert_eq!(noko.version.as_deref(), Some("1.16.5"));
        assert_eq!(noko.purl.as_deref(), Some("pkg:gem/nokogiri@1.16.5"));
    }

    #[test]
    fn gemfile_lock_platform_suffix_becomes_qualifier() {
        // Inline test: parse a spec line with a platform suffix directly.
        let spec = parse_spec_line("nokogiri (1.16.5-x86_64-linux)", "Gemfile.lock").unwrap();
        assert_eq!(spec.version, "1.16.5");
        assert_eq!(spec.platform.as_deref(), Some("x86_64-linux"));
        let purl = gem_purl(&spec.name, &spec.version, spec.platform.as_deref());
        assert_eq!(purl, "pkg:gem/nokogiri@1.16.5?platform=x86_64-linux");
    }

    #[test]
    fn gemfile_lock_no_platform_no_qualifier() {
        let spec = parse_spec_line("rake (13.2.1)", "Gemfile.lock").unwrap();
        assert!(spec.platform.is_none());
        let purl = gem_purl(&spec.name, &spec.version, spec.platform.as_deref());
        assert_eq!(purl, "pkg:gem/rake@13.2.1");
    }

    #[test]
    fn gemfile_lock_evidence_is_resolved() {
        let ctx = fixture_ctx("ruby");
        let out = RubyCataloger.catalog(&ctx).unwrap();
        let rake = out
            .iter()
            .find(|c| c.name == "rake" && c.matching_method == "gemfile_lock")
            .unwrap();
        assert_eq!(top_rung(&rake.evidence), Some(EvidenceKind::Resolved));
    }

    // -----------------------------------------------------------------------
    // CHECKSUMS section (Bundler 2.5+)
    // -----------------------------------------------------------------------

    #[test]
    fn checksums_section_attaches_sha256() {
        use std::io::Write;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("Gemfile.lock");
        let mut f = std::fs::File::create(&lock_path).unwrap();
        f.write_all(
            b"GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.2.1)\n\nCHECKSUMS\n    rake (13.2.1) sha256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n\nBUNDLED WITH\n   2.5.9\n",
        ).unwrap();
        let files = vec![lock_path];
        let ctx = CatalogContext::new(dir.path().to_path_buf(), files);
        let out = RubyCataloger.catalog(&ctx).unwrap();
        let rake = out
            .iter()
            .find(|c| c.name == "rake" && c.matching_method == "gemfile_lock")
            .unwrap();
        assert!(rake.hashes.len() == 1, "CHECKSUMS sha256 must attach");
        assert_eq!(rake.hashes[0].alg, "SHA-256");
        assert_eq!(
            rake.hashes[0].value_hex,
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }

    // -----------------------------------------------------------------------
    // Gemfile declared lane
    // -----------------------------------------------------------------------

    #[test]
    fn gemfile_declared_names_are_present() {
        let ctx = fixture_ctx("ruby");
        let out = RubyCataloger.catalog(&ctx).unwrap();
        let declared: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "gemfile")
            .collect();
        let names: Vec<_> = declared.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"nokogiri"));
        assert!(names.contains(&"rake"));
        assert!(names.contains(&"rspec"));
    }

    #[test]
    fn gemfile_declared_evidence_is_declared() {
        let ctx = fixture_ctx("ruby");
        let out = RubyCataloger.catalog(&ctx).unwrap();
        let nokogiri_decl = out
            .iter()
            .find(|c| c.name == "nokogiri" && c.matching_method == "gemfile")
            .unwrap();
        assert_eq!(
            top_rung(&nokogiri_decl.evidence),
            Some(EvidenceKind::Declared)
        );
    }

    #[test]
    fn gemfile_declared_gets_purl_from_lock() {
        let ctx = fixture_ctx("ruby");
        let out = RubyCataloger.catalog(&ctx).unwrap();
        let nokogiri_decl = out
            .iter()
            .find(|c| c.name == "nokogiri" && c.matching_method == "gemfile")
            .unwrap();
        // PURL uses the resolved version from the lockfile.
        assert_eq!(
            nokogiri_decl.purl.as_deref(),
            Some("pkg:gem/nokogiri@1.16.5")
        );
    }

    // -----------------------------------------------------------------------
    // Detect
    // -----------------------------------------------------------------------

    #[test]
    fn detect_true_for_gemfile_lock() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/Gemfile.lock".into()]);
        assert!(RubyCataloger.detect(&ctx));
    }

    #[test]
    fn detect_false_without_ruby_files() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/Cargo.toml".into()]);
        assert!(!RubyCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // merge_by_identity
    // -----------------------------------------------------------------------

    #[test]
    fn gemfile_and_lock_merge_to_one_component() {
        let ctx = fixture_ctx("ruby");
        let raw = RubyCataloger.catalog(&ctx).unwrap();
        let merged = crate::merge_by_identity(raw);
        // nokogiri from Gemfile (Declared) and Gemfile.lock (Resolved) → 1 component.
        let noko: Vec<_> = merged
            .iter()
            .filter(|c| c.purl.as_deref() == Some("pkg:gem/nokogiri@1.16.5"))
            .collect();
        assert_eq!(noko.len(), 1, "nokogiri must collapse to 1 component");
        assert!(noko[0]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Declared));
        assert!(noko[0]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Resolved));
    }

    // -----------------------------------------------------------------------
    // Helper unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn split_version_platform_bare_semver() {
        let (v, p) = split_version_platform("1.16.5");
        assert_eq!(v, "1.16.5");
        assert!(p.is_none());
    }

    #[test]
    fn split_version_platform_with_platform() {
        let (v, p) = split_version_platform("1.16.5-x86_64-linux");
        assert_eq!(v, "1.16.5");
        assert_eq!(p.as_deref(), Some("x86_64-linux"));
    }

    #[test]
    fn split_version_platform_multibyte_does_not_panic() {
        // Untrusted Gemfile.lock: a multibyte char before the `-platform` split
        // must not slice mid-codepoint (char index vs byte slice mismatch).
        // "é" is 2 bytes, so a char index would land mid-codepoint on byte slicing.
        let (v, p) = split_version_platform("1.0\u{00e9}-x86_64-linux");
        assert_eq!(v, "1.0\u{00e9}");
        assert_eq!(p.as_deref(), Some("x86_64-linux"));
    }

    #[test]
    fn parse_spec_line_multibyte_version_does_not_panic() {
        // End-to-end: a 4-space spec line with a multibyte version must parse.
        let spec = parse_spec_line("somegem (1.0\u{00e9}-x86_64-linux)", "Gemfile.lock").unwrap();
        assert_eq!(spec.version, "1.0\u{00e9}");
        assert_eq!(spec.platform.as_deref(), Some("x86_64-linux"));
    }

    #[test]
    fn extract_first_string_double_quoted() {
        assert_eq!(
            extract_first_string("\"nokogiri\", \">= 1.15\""),
            "nokogiri"
        );
    }

    #[test]
    fn extract_first_string_single_quoted() {
        assert_eq!(extract_first_string("'rake'"), "rake");
    }
}
