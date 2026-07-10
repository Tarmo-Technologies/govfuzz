// SPDX-License-Identifier: Apache-2.0

//! Cargo ecosystem cataloger: reads `Cargo.lock` (Resolved + checksums) and
//! `Cargo.toml` `[dependencies]` (Declared) and emits typed components that
//! `merge_by_identity` collapses into single pinned entries.
//!
//! The project-self `[package]` component is intentionally left to
//! `native_manifest::CargoCataloger`; this cataloger emits **only dependency**
//! components.  Root/workspace members in `Cargo.lock` (entries with neither
//! `source` nor `checksum`) are skipped.
//!
//! # Merge strategy
//! Both the Declared (manifest range) and Resolved (lock pin) components are
//! emitted with the resolved PURL (`pkg:cargo/<name>@<pinned_version>`) when the
//! name is found in the lockfile.  This makes `merge_by_identity` collapse them
//! via `ComponentKey::Purl` so the merged component carries both evidence rungs
//! while the Resolved fields (exact version, checksum) win.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::{Component, HashRef};
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct CargoCataloger;

impl Cataloger for CargoCataloger {
    fn ecosystem(&self) -> &str {
        "cargo"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("Cargo.lock").next().is_some()
            || ctx.files_named("Cargo.toml").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();

        // Build a name → (version, checksum) index from the lockfile(s) so that
        // manifest-declared components can be assigned the resolved PURL.
        let mut lock_index: HashMap<String, LockEntry> = HashMap::new();
        for lock_path in discover_lock_files(ctx) {
            let rel = relative_path(&ctx.root, lock_path);
            for entry in parse_lock_entries(lock_path, &rel)? {
                // In the (unlikely) case of multiple lock files, first wins.
                lock_index
                    .entry(entry.name.clone())
                    .or_insert_with(|| LockEntry { ..entry.clone() });
                // Also emit the Resolved component directly.
                out.push(resolved_component(entry));
            }
        }

        // Cargo.toml [dependencies]: Declared lane.
        for manifest_path in ctx.files_named("Cargo.toml") {
            let rel = relative_path(&ctx.root, manifest_path);
            let declared = parse_manifest_deps(manifest_path, &rel, &lock_index)?;
            out.extend(declared);
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Internal data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LockEntry {
    name: String,
    version: String,
    checksum: Option<String>,
    relative: String,
}

fn resolved_component(entry: LockEntry) -> Component {
    let hashes = entry
        .checksum
        .as_deref()
        .map(|hex| {
            vec![HashRef {
                alg: "SHA-256".to_owned(),
                value_hex: hex.to_owned(),
            }]
        })
        .unwrap_or_default();

    let evidence_source = format!("{}:[[package]] {}", entry.relative, entry.name);

    Component {
        component_ref: String::new(),
        name: entry.name.clone(),
        version: Some(entry.version.clone()),
        ecosystem: "cargo".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(purl::cargo(&entry.name, &entry.version)),
        cpe: None,
        sha256: entry.checksum.clone(),
        hashes,
        identity_confidence: "high".to_owned(),
        matching_method: "cargo_lock".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Resolved, evidence_source)],
        runtime_harnesses: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Cargo.lock parser
// ---------------------------------------------------------------------------

fn parse_lock_entries(path: &Path, relative: &str) -> Result<Vec<LockEntry>, CatalogError> {
    let source = read_to_string(path)?;
    let value: toml::Value = toml::from_str(&source).map_err(|e| CatalogError::Malformed {
        kind: "Cargo.lock".to_owned(),
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;

    let Some(packages) = value.get("package").and_then(|v| v.as_array()) else {
        return Ok(vec![]);
    };

    // Legacy v1 (no top-level `version`) stores checksums in the [metadata] table
    // keyed `"checksum <name> <ver> (<source>)" = "<hex>"`. Index them by
    // (name, version) so packages without an inline checksum can look theirs up.
    let v1_checksums = parse_v1_metadata_checksums(&value);

    let mut out = Vec::new();
    for pkg in packages {
        let Some(table) = pkg.as_table() else {
            continue;
        };

        let has_source = table.contains_key("source");
        let has_checksum = table.contains_key("checksum");

        // Skip root/workspace members: they have neither source nor checksum
        // (nor a v1 [metadata] checksum entry).
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(version) = table.get("version").and_then(|v| v.as_str()) else {
            continue;
        };

        // Inline checksum (v2+) wins; otherwise fall back to the v1 [metadata]
        // table for a sourced package.
        let checksum = table
            .get("checksum")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| {
                if has_source {
                    v1_checksums
                        .get(&(name.to_owned(), version.to_owned()))
                        .cloned()
                } else {
                    None
                }
            });

        if !has_source && !has_checksum && checksum.is_none() {
            continue;
        }

        out.push(LockEntry {
            name: name.to_owned(),
            version: version.to_owned(),
            checksum,
            relative: relative.to_owned(),
        });
    }

    Ok(out)
}

/// Parse the legacy v1 `[metadata]` checksum table into `(name, version) → hex`.
/// Keys look like `checksum <name> <ver> (<source>)`; the value is the hex digest
/// (or the sentinel `"<none>"` for path/git deps, which we ignore).
fn parse_v1_metadata_checksums(value: &toml::Value) -> HashMap<(String, String), String> {
    let mut map = HashMap::new();
    let Some(meta) = value.get("metadata").and_then(|v| v.as_table()) else {
        return map;
    };
    for (key, val) in meta {
        let Some(rest) = key.strip_prefix("checksum ") else {
            continue;
        };
        let Some(hex) = val.as_str() else {
            continue;
        };
        if hex.is_empty() || hex == "<none>" {
            continue;
        }
        // `<name> <ver> (<source>)` — the source begins at the first '('.
        let before_source = rest.split('(').next().unwrap_or(rest);
        let mut toks = before_source.split_whitespace();
        let (Some(name), Some(ver)) = (toks.next(), toks.next()) else {
            continue;
        };
        map.insert((name.to_owned(), ver.to_owned()), hex.to_owned());
    }
    map
}

// ---------------------------------------------------------------------------
// Cargo.toml [dependencies] parser
// ---------------------------------------------------------------------------

fn parse_manifest_deps(
    path: &Path,
    relative: &str,
    lock_index: &HashMap<String, LockEntry>,
) -> Result<Vec<Component>, CatalogError> {
    let source = read_to_string(path)?;
    let value: toml::Value = toml::from_str(&source).map_err(|e| CatalogError::Malformed {
        kind: "Cargo.toml".to_owned(),
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;

    let mut out = Vec::new();

    // Top-level [dependencies] / [dev-dependencies] / [build-dependencies].
    for section in DEP_SECTIONS {
        if let Some(deps) = value.get(*section).and_then(|v| v.as_table()) {
            collect_dep_table(deps, relative, lock_index, &mut out);
        }
    }

    // Platform-gated deps: [target.'cfg(...)'.dependencies] (and the dev/build
    // variants). Without a Cargo.lock these would otherwise be silently dropped,
    // losing platform crates like winapi/libc/nix.
    if let Some(targets) = value.get("target").and_then(|v| v.as_table()) {
        for cfg_value in targets.values() {
            let Some(cfg_table) = cfg_value.as_table() else {
                continue;
            };
            for section in DEP_SECTIONS {
                if let Some(deps) = cfg_table.get(*section).and_then(|v| v.as_table()) {
                    collect_dep_table(deps, relative, lock_index, &mut out);
                }
            }
        }
    }

    Ok(out)
}

/// The three Cargo dependency sections, shared between the top-level and the
/// per-`[target.'cfg(...)']` tables.
const DEP_SECTIONS: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];

/// Emit a Declared component for every dependency in one `[dependencies]`-shaped
/// table (handles `package =` renames, exact-pin vs range, lockfile join).
fn collect_dep_table(
    deps: &toml::map::Map<String, toml::Value>,
    relative: &str,
    lock_index: &HashMap<String, LockEntry>,
    out: &mut Vec<Component>,
) {
    for (key, dep_value) in deps {
        // Resolve the real package name (handles `package = "real"` renames).
        let pkg_name = dep_value
            .as_table()
            .and_then(|t| t.get("package"))
            .and_then(|v| v.as_str())
            .unwrap_or(key.as_str())
            .to_owned();

        // Extract the version spec (may be a range like "0.8").
        let version_str = match dep_value {
            toml::Value::String(s) => Some(s.clone()),
            toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()).map(str::to_owned),
            _ => None,
        };

        // A Cargo.toml version spec is a RANGE by default (`^1.2`, `0.8`).
        // Only an exact `=x.y.z` is a real version; otherwise the field must
        // stay None so `identity_key` never treats a range as a version.
        // (Mirrors alire.rs's declared path.)
        let exact_from_spec = version_str.as_deref().and_then(exact_cargo_version);

        // If the name is in the lockfile index, use the resolved PURL + the
        // exact lock pin so that `merge_by_identity` can collapse this Declared
        // component with the Resolved component emitted from the lockfile.
        let (version_field, purl_value) = if let Some(entry) = lock_index.get(&pkg_name) {
            (
                Some(entry.version.clone()),
                Some(purl::cargo(&pkg_name, &entry.version)),
            )
        } else {
            // No lockfile or lock miss. Use exact `=x.y.z` pin when available;
            // otherwise emit a name-only PURL so downstream SCA tools can match
            // by package name. The `version` field stays None for ranges — a
            // range is not a version (see `exact_cargo_version`).
            let purl = exact_from_spec
                .as_deref()
                .map(|exact| purl::cargo(&pkg_name, exact))
                .or_else(|| Some(purl::cargo_nameonly(&pkg_name)));
            (exact_from_spec.clone(), purl)
        };

        out.push(Component {
            component_ref: String::new(),
            name: pkg_name,
            version: version_field,
            ecosystem: "cargo".to_owned(),
            group: None,
            component_type: "library".to_owned(),
            supplier: None,
            license: None,
            purl: purl_value,
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "high".to_owned(),
            matching_method: "cargo_manifest".to_owned(),
            evidence: vec![Evidence::new(EvidenceKind::Declared, relative)],
            runtime_harnesses: Vec::new(),
        });
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The lockfiles to resolve against. A canonical `Cargo.lock` (anywhere in the
/// tree) is authoritative; only when none exists do we fall back to sibling /
/// CI variant lockfiles (`1.63.Cargo.lock`, `ci-lockfiles/*.Cargo.lock`,
/// `Cargo.lock.msrv`, …) so a manifest-only SBOM still becomes a resolved graph.
fn discover_lock_files(ctx: &CatalogContext) -> Vec<&Path> {
    let canonical: Vec<&Path> = ctx.files_named("Cargo.lock").map(|p| p.as_path()).collect();
    if !canonical.is_empty() {
        return canonical;
    }
    ctx.files
        .iter()
        .filter(|p| is_variant_lockfile(p))
        .map(|p| p.as_path())
        .collect()
}

/// A non-canonical Cargo lockfile variant: a basename that contains the literal
/// `Cargo.lock` but is not exactly `Cargo.lock` (e.g. `1.63.Cargo.lock`,
/// `Cargo.lock.min`, `msrv-Cargo.lock`). Restricting to names carrying
/// `Cargo.lock` avoids parsing unrelated `*.lock` files as Cargo lockfiles.
fn is_variant_lockfile(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name != "Cargo.lock" && name.contains("Cargo.lock")
}

/// Return the exact version from a Cargo version spec iff it is an exact pin
/// (`=x.y.z`). Ranges (`^1.2`, `~1`, `>=1`, bare `0.8`, `*`) yield `None`.
fn exact_cargo_version(spec: &str) -> Option<String> {
    let trimmed = spec.trim();
    let exact = trimmed.strip_prefix('=')?.trim();
    // `==` / `=>` etc. are not exact pins.
    if exact.is_empty() || exact.starts_with('=') {
        return None;
    }
    Some(exact.to_owned())
}

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

    /// Build a `CatalogContext` rooted at `tests/fixtures/<name>` with all
    /// regular files recursively listed.
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

    #[test]
    fn lockfile_yields_resolved_deps_with_hashes_excluding_root() {
        let ctx = fixture_ctx("cargo");
        let out = CargoCataloger.catalog(&ctx).unwrap();
        // Root crate "demo" (no source/checksum) is excluded; rand + rand_core remain.
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"rand") && names.contains(&"rand_core"));
        assert!(!names.contains(&"demo"));
        let rand = out
            .iter()
            .find(|c| c.name == "rand" && c.matching_method == "cargo_lock")
            .unwrap();
        assert_eq!(rand.version.as_deref(), Some("0.8.5"));
        assert_eq!(rand.purl.as_deref(), Some("pkg:cargo/rand@0.8.5"));
        assert_eq!(rand.hashes[0].alg, "SHA-256");
        assert_eq!(
            rand.hashes[0].value_hex,
            "34af8d1a0e25924bc5b7c43c079c942339d8f0a8b57c39049bef581b46327404"
        );
        assert_eq!(top_rung(&rand.evidence), Some(EvidenceKind::Resolved));
    }

    #[test]
    fn manifest_dep_merges_with_lockfile_pin() {
        let ctx = fixture_ctx("cargo");
        let merged = crate::merge_by_identity(CargoCataloger.catalog(&ctx).unwrap());
        // rand appears once: Declared(Cargo.toml "0.8") upgraded to Resolved(0.8.5).
        let rand: Vec<_> = merged.iter().filter(|c| c.name == "rand").collect();
        assert_eq!(rand.len(), 1);
        assert_eq!(rand[0].version.as_deref(), Some("0.8.5"));
        assert!(rand[0]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Declared));
        assert!(rand[0]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Resolved));
    }

    fn temp_ctx(files: &[(&str, &str)]) -> (tempfile::TempDir, CatalogContext) {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let mut paths = Vec::new();
        for (name, body) in files {
            let p = dir.path().join(name);
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
    fn manifest_range_without_lock_has_no_version_but_nameonly_purl() {
        // A Cargo.toml range with NO lockfile must NOT store the range in the
        // `version` field (identity_key would use a range as a version).
        // However a name-only PURL is emitted so downstream SCA can match by name.
        let (_d, ctx) = temp_ctx(&[(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"^1.2\"\n",
        )]);
        let out = CargoCataloger.catalog(&ctx).unwrap();
        let serde = out
            .iter()
            .find(|c| c.name == "serde" && c.matching_method == "cargo_manifest")
            .expect("serde declared must be present");
        assert!(
            serde.version.is_none(),
            "a range must not become a version: {:?}",
            serde.version
        );
        // Name-only PURL — no @version suffix.
        assert_eq!(
            serde.purl.as_deref(),
            Some("pkg:cargo/serde"),
            "range dep should get a name-only PURL"
        );
    }

    #[test]
    fn manifest_exact_eq_without_lock_keeps_version() {
        // An exact `=x.y.z` pin (no lockfile) keeps its version + PURL.
        let (_d, ctx) = temp_ctx(&[(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"=1.2.3\"\n",
        )]);
        let out = CargoCataloger.catalog(&ctx).unwrap();
        let serde = out
            .iter()
            .find(|c| c.name == "serde" && c.matching_method == "cargo_manifest")
            .expect("serde declared must be present");
        assert_eq!(serde.version.as_deref(), Some("1.2.3"));
        assert_eq!(serde.purl.as_deref(), Some("pkg:cargo/serde@1.2.3"));
    }

    #[test]
    fn v1_lock_metadata_checksum_is_resolved() {
        // Legacy Cargo.lock v1: no top-level `version`, no inline `checksum` on
        // each [[package]] — the hashes live in the [metadata] table keyed
        // "checksum <name> <ver> (<source>)" = "<hex>".
        let (_d, ctx) = temp_ctx(&[(
            "Cargo.lock",
            "[[package]]\n\
             name = \"libc\"\n\
             version = \"0.2.155\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             \n\
             [metadata]\n\
             \"checksum libc 0.2.155 (registry+https://github.com/rust-lang/crates.io-index)\" = \"97b3888a4b6a31b2c12a1d33a0fa6c7c2f01b94a8c2f3a3f6a0e7f5b6e4d3c2b\"\n",
        )]);
        let out = CargoCataloger.catalog(&ctx).unwrap();
        let libc = out
            .iter()
            .find(|c| c.name == "libc" && c.matching_method == "cargo_lock")
            .expect("libc resolved from v1 lock");
        assert_eq!(libc.version.as_deref(), Some("0.2.155"));
        assert_eq!(
            libc.sha256.as_deref(),
            Some("97b3888a4b6a31b2c12a1d33a0fa6c7c2f01b94a8c2f3a3f6a0e7f5b6e4d3c2b")
        );
        assert_eq!(libc.hashes.len(), 1);
        assert_eq!(libc.hashes[0].alg, "SHA-256");
        assert_eq!(
            libc.hashes[0].value_hex,
            "97b3888a4b6a31b2c12a1d33a0fa6c7c2f01b94a8c2f3a3f6a0e7f5b6e4d3c2b"
        );
    }

    #[test]
    fn manifest_range_with_lock_uses_pinned_version() {
        // When the dep IS in the lockfile, the Declared component's version is
        // the exact lock pin (mirrors alire's declared_component_stub).
        let (_d, ctx) = temp_ctx(&[
            (
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"^1.0\"\n",
            ),
            (
                "Cargo.lock",
                "version = 3\n[[package]]\nname = \"serde\"\nversion = \"1.0.197\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"3fb1c873e1b9b056a4dc4c0c198b24c3ffa059243875552b2bd0933b1aee4ce2\"\n",
            ),
        ]);
        let out = CargoCataloger.catalog(&ctx).unwrap();
        let serde_decl = out
            .iter()
            .find(|c| c.name == "serde" && c.matching_method == "cargo_manifest")
            .expect("serde declared must be present");
        assert_eq!(serde_decl.version.as_deref(), Some("1.0.197"));
        assert_eq!(serde_decl.purl.as_deref(), Some("pkg:cargo/serde@1.0.197"));
    }

    #[test]
    fn target_cfg_dependencies_are_catalogued() {
        // Platform-gated deps under [target.'cfg(...)'] must not be dropped when
        // there is no Cargo.lock (winapi/libc/nix were silently lost before).
        let (_d, ctx) = temp_ctx(&[(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\
             [dependencies]\nserde = \"1\"\n\
             [target.'cfg(windows)'.dependencies]\nwinapi = \"0.3\"\n\
             [target.'cfg(unix)'.dev-dependencies]\nnix = \"0.27\"\n",
        )]);
        let out = CargoCataloger.catalog(&ctx).unwrap();
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"winapi"),
            "cfg(windows) dependency dropped: {names:?}"
        );
        assert!(
            names.contains(&"nix"),
            "cfg(unix) dev-dependency dropped: {names:?}"
        );
        let winapi = out.iter().find(|c| c.name == "winapi").unwrap();
        assert_eq!(winapi.purl.as_deref(), Some("pkg:cargo/winapi"));
    }

    #[test]
    fn variant_lockfile_used_when_no_canonical_lock() {
        // No canonical Cargo.lock, but a CI variant lock (`1.63.Cargo.lock`)
        // pins serde — the resolved graph must still be recovered.
        let (_d, ctx) = temp_ctx(&[
            (
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"^1\"\n",
            ),
            (
                "1.63.Cargo.lock",
                "version = 3\n[[package]]\nname = \"serde\"\nversion = \"1.0.150\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"3fb1c873e1b9b056a4dc4c0c198b24c3ffa059243875552b2bd0933b1aee4ce2\"\n",
            ),
        ]);
        let out = CargoCataloger.catalog(&ctx).unwrap();
        let serde_decl = out
            .iter()
            .find(|c| c.name == "serde" && c.matching_method == "cargo_manifest")
            .expect("serde declared present");
        assert_eq!(serde_decl.version.as_deref(), Some("1.0.150"));
        assert_eq!(serde_decl.purl.as_deref(), Some("pkg:cargo/serde@1.0.150"));
    }

    #[test]
    fn canonical_lock_preferred_over_variant() {
        // With BOTH a canonical Cargo.lock and a variant present, the variant is
        // ignored (the canonical lock is authoritative).
        let (_d, ctx) = temp_ctx(&[
            (
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"^1\"\n",
            ),
            (
                "Cargo.lock",
                "version = 3\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"3fb1c873e1b9b056a4dc4c0c198b24c3ffa059243875552b2bd0933b1aee4ce2\"\n",
            ),
            (
                "1.63.Cargo.lock",
                "version = 3\n[[package]]\nname = \"serde\"\nversion = \"1.0.100\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            ),
        ]);
        let out = CargoCataloger.catalog(&ctx).unwrap();
        let serde_decl = out
            .iter()
            .find(|c| c.name == "serde" && c.matching_method == "cargo_manifest")
            .expect("serde declared present");
        assert_eq!(
            serde_decl.version.as_deref(),
            Some("1.0.200"),
            "canonical Cargo.lock must win over the variant"
        );
    }
}
