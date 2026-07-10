// SPDX-License-Identifier: Apache-2.0

//! PHP (Composer / Packagist) ecosystem cataloger.
//!
//! **Declared**: `composer.json` `require`/`require-dev` map.
//! Platform pseudo-packages (no `/` in the key: `php`, `ext-*`, `lib-*`, etc.)
//! are **filtered** — they have no PURL.
//!
//! **Resolved** (+hash): `composer.lock` `packages` (prod) and `packages-dev`
//! (dev) arrays. `dist.shasum` = SHA-1 hex (40 chars, often empty) — emit as
//! `HashRef{alg:"SHA-1", ...}` only when non-empty. The `content-hash` is a
//! composer.json freshness fingerprint — never emitted as a component hash.
//! `dist.reference`/`source.reference` = git commit SHA (provenance, not a
//! content hash) — stored as an evidence locator, not a `HashRef`.
//!
//! # PURL
//! `pkg:composer/<vendor>/<name>@<version>`. Vendor and name are BOTH lowercased.
//! The `id` in composer.json is already `vendor/name`; split on first `/`.
//! Keys with no `/` are platform pseudo-packages (filtered before PURL creation).

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::{Component, HashRef};
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct PhpCataloger;

impl Cataloger for PhpCataloger {
    fn ecosystem(&self) -> &str {
        "composer"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("composer.json").next().is_some()
            || ctx.files_named("composer.lock").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();

        // Build name → LockPkg index from lockfiles.
        let mut lock_index: HashMap<String, LockPkg> = HashMap::new();

        for path in ctx.files_named("composer.lock") {
            let rel = relative_path(&ctx.root, path);
            for pkg in parse_composer_lock(path, &rel)? {
                lock_index
                    .entry(pkg.name.to_ascii_lowercase())
                    .or_insert_with(|| pkg.clone());
                out.push(lock_pkg_to_component(pkg));
            }
        }

        // composer.json: Declared lane.
        for path in ctx.files_named("composer.json") {
            let rel = relative_path(&ctx.root, path);
            for dep in parse_composer_json(path, &rel)? {
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
struct LockPkg {
    name: String, // vendor/name (lowercase)
    version: String,
    sha1: Option<String>,
    git_reference: Option<String>,
    relative: String,
}

#[derive(Debug, Clone)]
struct DeclaredDep {
    name: String, // vendor/name (lowercase)
    relative: String,
}

fn lock_pkg_to_component(pkg: LockPkg) -> Component {
    let purl_val = purl::composer(&pkg.name, &pkg.version);
    let hashes = pkg
        .sha1
        .as_deref()
        .map(|hex| {
            vec![HashRef {
                alg: "SHA-1".to_owned(),
                value_hex: hex.to_owned(),
            }]
        })
        .unwrap_or_default();
    let mut evidence = vec![Evidence::new(
        EvidenceKind::Resolved,
        format!("{}:{}", pkg.relative, pkg.name),
    )];
    // Store git commit SHA as a provenance note (not a content hash).
    if let Some(git_ref) = &pkg.git_reference {
        evidence.push(Evidence {
            kind: EvidenceKind::Resolved,
            source: format!("{}:{} (git)", pkg.relative, pkg.name),
            locator: Some(format!("git:{git_ref}")),
        });
    }
    Component {
        component_ref: String::new(),
        name: pkg.name.clone(),
        version: Some(pkg.version.clone()),
        ecosystem: "composer".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(purl_val),
        cpe: None,
        sha256: None,
        hashes,
        identity_confidence: "high".to_owned(),
        matching_method: "composer_lock".to_owned(),
        evidence,
        runtime_harnesses: Vec::new(),
    }
}

fn declared_component(dep: DeclaredDep, lock_index: &HashMap<String, LockPkg>) -> Component {
    let source = format!("{}:{}", dep.relative, dep.name);
    let purl_val = if let Some(pkg) = lock_index.get(&dep.name) {
        Some(purl::composer(&dep.name, &pkg.version))
    } else {
        // No lockfile — emit PURL without version (ranges are not valid PURL versions).
        None
    };
    Component {
        component_ref: String::new(),
        name: dep.name,
        version: None,
        ecosystem: "composer".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "medium".to_owned(),
        matching_method: "composer_json".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, source)],
        runtime_harnesses: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// composer.lock parser
// ---------------------------------------------------------------------------

fn parse_composer_lock(path: &Path, relative: &str) -> Result<Vec<LockPkg>, CatalogError> {
    let source = read_to_string(path)?;
    let root: serde_json::Value =
        serde_json::from_str(&source).map_err(|e| CatalogError::Malformed {
            kind: "composer.lock".to_owned(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;

    let mut out = Vec::new();

    // Catalog both `packages` (prod) and `packages-dev` (dev).
    for section in &["packages", "packages-dev"] {
        let Some(arr) = root.get(*section).and_then(|v| v.as_array()) else {
            continue;
        };
        for pkg in arr {
            let Some(name_raw) = pkg.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(version) = pkg.get("version").and_then(|v| v.as_str()) else {
                continue;
            };

            // Lowercase vendor/name.
            let name = name_raw.to_ascii_lowercase();

            // `dist.shasum` = SHA-1 hex (often empty).
            let sha1 = pkg
                .get("dist")
                .and_then(|d| d.get("shasum"))
                .and_then(|v| v.as_str())
                .filter(|s| s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()))
                .map(str::to_owned);

            // Git reference from dist.reference or source.reference (provenance only).
            let git_reference = pkg
                .get("dist")
                .and_then(|d| d.get("reference"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    pkg.get("source")
                        .and_then(|s| s.get("reference"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                })
                .map(str::to_owned);

            out.push(LockPkg {
                name,
                version: version.to_owned(),
                sha1,
                git_reference,
                relative: relative.to_owned(),
            });
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// composer.json parser (Declared)
// ---------------------------------------------------------------------------

fn parse_composer_json(path: &Path, relative: &str) -> Result<Vec<DeclaredDep>, CatalogError> {
    let source = read_to_string(path)?;
    let root: serde_json::Value =
        serde_json::from_str(&source).map_err(|e| CatalogError::Malformed {
            kind: "composer.json".to_owned(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;

    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for section in &["require", "require-dev"] {
        let Some(map) = root.get(*section).and_then(|v| v.as_object()) else {
            continue;
        };
        for key in map.keys() {
            // Filter platform pseudo-packages: keys with no `/`.
            if !key.contains('/') {
                continue;
            }
            let name = key.to_ascii_lowercase();
            if seen.insert(name.clone()) {
                out.push(DeclaredDep {
                    name,
                    relative: relative.to_owned(),
                });
            }
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
    // composer.lock parsing
    // -----------------------------------------------------------------------

    #[test]
    fn composer_lock_yields_packages_and_dev() {
        let ctx = fixture_ctx("php");
        let out = PhpCataloger.catalog(&ctx).unwrap();
        let lock_comps: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "composer_lock")
            .collect();
        let names: Vec<_> = lock_comps.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"guzzlehttp/guzzle"));
        assert!(names.contains(&"guzzlehttp/promises"));
        assert!(
            names.contains(&"phpunit/phpunit"),
            "dev package must be included"
        );
    }

    #[test]
    fn composer_lock_purl_lowercased() {
        let ctx = fixture_ctx("php");
        let out = PhpCataloger.catalog(&ctx).unwrap();
        let guzzle = out
            .iter()
            .find(|c| c.name == "guzzlehttp/guzzle" && c.matching_method == "composer_lock")
            .unwrap();
        assert_eq!(guzzle.version.as_deref(), Some("7.8.0"));
        assert_eq!(
            guzzle.purl.as_deref(),
            Some("pkg:composer/guzzlehttp/guzzle@7.8.0")
        );
    }

    #[test]
    fn composer_lock_sha1_recorded_when_non_empty() {
        let ctx = fixture_ctx("php");
        let out = PhpCataloger.catalog(&ctx).unwrap();
        let guzzle = out
            .iter()
            .find(|c| c.name == "guzzlehttp/guzzle" && c.matching_method == "composer_lock")
            .unwrap();
        assert_eq!(guzzle.hashes.len(), 1, "guzzle has a non-empty shasum");
        assert_eq!(guzzle.hashes[0].alg, "SHA-1");
        assert_eq!(
            guzzle.hashes[0].value_hex,
            "abcdef1234567890abcdef1234567890abcdef12"
        );
    }

    #[test]
    fn composer_lock_empty_shasum_not_emitted() {
        let ctx = fixture_ctx("php");
        let out = PhpCataloger.catalog(&ctx).unwrap();
        let promises = out
            .iter()
            .find(|c| c.name == "guzzlehttp/promises" && c.matching_method == "composer_lock")
            .unwrap();
        assert!(
            promises.hashes.is_empty(),
            "empty shasum must not emit a HashRef"
        );
    }

    #[test]
    fn composer_lock_content_hash_not_emitted_as_component() {
        let ctx = fixture_ctx("php");
        let out = PhpCataloger.catalog(&ctx).unwrap();
        // content-hash is a composer.json fingerprint — must never be a component.
        let content_hash = "d9aef3b2b3c88b28fefb4b5f2d4a5e6c8f0a1b3c4d5e6f7a8b9c0d1e2f3a4b5";
        for c in &out {
            assert_ne!(
                c.version.as_deref(),
                Some(content_hash),
                "content-hash must not be a version"
            );
            assert_ne!(
                c.name, content_hash,
                "content-hash must not be a component name"
            );
        }
    }

    #[test]
    fn composer_lock_git_reference_as_evidence_locator() {
        let ctx = fixture_ctx("php");
        let out = PhpCataloger.catalog(&ctx).unwrap();
        let guzzle = out
            .iter()
            .find(|c| c.name == "guzzlehttp/guzzle" && c.matching_method == "composer_lock")
            .unwrap();
        // Git reference must be stored as a provenance evidence note.
        let has_git = guzzle.evidence.iter().any(|e| {
            e.locator
                .as_deref()
                .map(|l| l.starts_with("git:"))
                .unwrap_or(false)
        });
        assert!(has_git, "git reference must be an evidence locator");
    }

    #[test]
    fn composer_lock_evidence_is_resolved() {
        let ctx = fixture_ctx("php");
        let out = PhpCataloger.catalog(&ctx).unwrap();
        let guzzle = out
            .iter()
            .find(|c| c.name == "guzzlehttp/guzzle" && c.matching_method == "composer_lock")
            .unwrap();
        assert_eq!(top_rung(&guzzle.evidence), Some(EvidenceKind::Resolved));
    }

    // -----------------------------------------------------------------------
    // composer.json declared lane
    // -----------------------------------------------------------------------

    #[test]
    fn composer_json_filters_platform_pseudo_packages() {
        let ctx = fixture_ctx("php");
        let out = PhpCataloger.catalog(&ctx).unwrap();
        let declared: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "composer_json")
            .collect();
        let names: Vec<_> = declared.iter().map(|c| c.name.as_str()).collect();
        // `php`, `ext-json`, `lib-curl` must NOT be in declared (no `/`).
        assert!(
            !names.contains(&"php"),
            "php pseudo-package must be filtered"
        );
        assert!(!names.contains(&"ext-json"), "ext-json must be filtered");
        assert!(!names.contains(&"lib-curl"), "lib-curl must be filtered");
        // Real packages must be present.
        assert!(
            names.contains(&"guzzlehttp/guzzle"),
            "guzzle must be declared"
        );
        assert!(
            names.contains(&"phpunit/phpunit"),
            "phpunit must be declared"
        );
    }

    #[test]
    fn composer_json_declared_evidence_is_declared() {
        let ctx = fixture_ctx("php");
        let out = PhpCataloger.catalog(&ctx).unwrap();
        let guzzle_decl = out
            .iter()
            .find(|c| c.name == "guzzlehttp/guzzle" && c.matching_method == "composer_json")
            .unwrap();
        assert_eq!(
            top_rung(&guzzle_decl.evidence),
            Some(EvidenceKind::Declared)
        );
    }

    #[test]
    fn composer_json_declared_gets_purl_from_lock() {
        let ctx = fixture_ctx("php");
        let out = PhpCataloger.catalog(&ctx).unwrap();
        let guzzle_decl = out
            .iter()
            .find(|c| c.name == "guzzlehttp/guzzle" && c.matching_method == "composer_json")
            .unwrap();
        assert_eq!(
            guzzle_decl.purl.as_deref(),
            Some("pkg:composer/guzzlehttp/guzzle@7.8.0")
        );
    }

    // -----------------------------------------------------------------------
    // Detect
    // -----------------------------------------------------------------------

    #[test]
    fn detect_true_for_composer_lock() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/composer.lock".into()]);
        assert!(PhpCataloger.detect(&ctx));
    }

    #[test]
    fn detect_true_for_composer_json() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/composer.json".into()]);
        assert!(PhpCataloger.detect(&ctx));
    }

    #[test]
    fn detect_false_without_php_files() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/Cargo.toml".into()]);
        assert!(!PhpCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // merge_by_identity
    // -----------------------------------------------------------------------

    #[test]
    fn composer_json_and_lock_merge_to_one_component() {
        let ctx = fixture_ctx("php");
        let raw = PhpCataloger.catalog(&ctx).unwrap();
        let merged = crate::merge_by_identity(raw);
        let guzzle: Vec<_> = merged
            .iter()
            .filter(|c| c.purl.as_deref() == Some("pkg:composer/guzzlehttp/guzzle@7.8.0"))
            .collect();
        assert_eq!(guzzle.len(), 1, "guzzle must collapse to 1 component");
        assert!(guzzle[0]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Declared));
        assert!(guzzle[0]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Resolved));
    }
}
