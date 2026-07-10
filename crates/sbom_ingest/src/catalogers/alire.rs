// SPDX-License-Identifier: Apache-2.0

//! Alire (Ada) ecosystem cataloger.
//!
//! **Declared**: `alire.toml` — project metadata (`name`/`version`) and
//! dependencies in two syntaxes:
//! - Repeated `[[depends-on]]` tables: each table may declare several crate
//!   keys with constraint strings.
//! - Inline `depends-on = [ {crate="^1.2"}, ... ]` array.
//!
//! Constraints ⇒ `EvidenceKind::Declared`.
//!
//! **Resolved**: `alire/alire.lock` OR `./alire.lock` (may be absent).
//! Each `[[solution.state]]` entry provides `crate`, `fulfilment`,
//! `[solution.state.release].version` (exact), and
//! `[solution.state.release.origin]` (git commit SHA or archive hashes).
//! `fulfilment != "solved"` ⇒ `release.version` is still used.
//!
//! Toolchain crates (`gnat`, `gprbuild`, `gnatprep`) are excluded from the
//! application SBOM.
//!
//! # PURL
//! `pkg:generic/<crate>@<version>` — no registered Alire PURL type.
//! The git commit SHA from `origin.commit` is recorded as a `vcs_url=` qualifier
//! when available; archive `origin.hashes` SHA-512/SHA-256 as `checksum=`.
//!
//! # Untrusted input
//! Both files are bounded (≤4 MiB). TOML parsing is structural; no eval.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::{Component, HashRef};
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Toolchain crate names excluded from the SBOM.
const TOOLCHAIN_CRATES: &[&str] = &["gnat", "gprbuild", "gnatprep"];

pub struct AlireCataloger;

impl Cataloger for AlireCataloger {
    fn ecosystem(&self) -> &str {
        "alire"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("alire.toml").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();

        for toml_path in ctx.files_named("alire.toml") {
            let rel = relative_path(&ctx.root, toml_path);

            // Build a lock index from alire/alire.lock or ./alire.lock.
            let lock_index = find_and_parse_lock(ctx, toml_path)?;

            // Parse declared deps from alire.toml.
            let declared = parse_alire_toml(toml_path, &rel)?;

            // Emit: if in lock index → Resolved; else → Declared.
            for dep in declared {
                let key = dep.name.to_ascii_lowercase();
                if is_toolchain(&key) {
                    continue;
                }
                if let Some(lock_entry) = lock_index.get(&key) {
                    out.push(lock_entry_to_component(lock_entry));
                    // Also emit a Declared evidence entry so merge_by_identity
                    // can record both.
                    let decl_source = format!("{}:{}", rel, dep.name);
                    out.push(declared_component_stub(
                        &dep.name,
                        &dep.constraint,
                        &rel,
                        &decl_source,
                        lock_entry,
                    ));
                } else {
                    let source = format!("{}:{}", rel, dep.name);
                    out.push(declared_only_component(&dep, &source));
                }
            }

            // Emit any Resolved lock entries not in the declared list (transitive).
            for (name, entry) in &lock_index {
                if is_toolchain(name) {
                    continue;
                }
                let already_emitted = out
                    .iter()
                    .any(|c| c.matching_method == "alire_lock" && c.name == entry.name);
                if !already_emitted {
                    out.push(lock_entry_to_component(entry));
                }
            }
        }

        Ok(out)
    }
}

fn is_toolchain(name: &str) -> bool {
    TOOLCHAIN_CRATES.contains(&name)
}

// ---------------------------------------------------------------------------
// alire.toml parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DeclaredDep {
    name: String,
    constraint: String,
}

fn parse_alire_toml(path: &Path, _relative: &str) -> Result<Vec<DeclaredDep>, CatalogError> {
    let source = read_bounded(path)?;
    let root: toml::Value = toml::from_str(&source).map_err(|e| CatalogError::Malformed {
        kind: "alire.toml".to_owned(),
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;

    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Both `[[depends-on]]` tables AND inline `depends-on = [ {..}, {..} ]` arrays
    // deserialize to a TOML array of tables. Each table carries one or more crates
    // in one of two shapes — `parse_depends_table` handles both.
    if let Some(toml::Value::Array(tables)) = root.get("depends-on") {
        for table in tables {
            match table {
                toml::Value::Table(t) => parse_depends_table(t, &mut seen, &mut out),
                // Defensive: a genuinely nested array of tables.
                toml::Value::Array(inner) => {
                    for item in inner {
                        if let toml::Value::Table(t) = item {
                            parse_depends_table(t, &mut seen, &mut out);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(out)
}

/// Parse a single depends-on table into `DeclaredDep`s, handling both shapes:
///  (1) `{ crate = "name", version = "^1.0" }` — explicit `crate`/`version` keys.
///  (2) `{ libhello = "^1.0", ada_toml = "~0.5" }` — each key IS a crate name.
fn parse_depends_table(
    t: &toml::map::Map<String, toml::Value>,
    seen: &mut std::collections::HashSet<String>,
    out: &mut Vec<DeclaredDep>,
) {
    // Shape (1): explicit `crate = "name"` (optionally `version = "constraint"`).
    if let Some(crate_name) = t.get("crate").and_then(|v| v.as_str()) {
        let constraint = t
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let key = crate_name.to_ascii_lowercase();
        if seen.insert(key.clone()) {
            out.push(DeclaredDep {
                name: key,
                constraint,
            });
        }
        return;
    }

    // Shape (2): each `key = "constraint"` pair is a crate. Skip non-string
    // values (e.g. dynamic `'case(os)'` sub-tables).
    for (crate_name, constraint_val) in t {
        let toml::Value::String(constraint) = constraint_val else {
            continue;
        };
        let key = crate_name.to_ascii_lowercase();
        if seen.insert(key.clone()) {
            out.push(DeclaredDep {
                name: key,
                constraint: constraint.clone(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// alire.lock parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LockEntry {
    name: String,    // crate name from solution.state.crate
    version: String, // exact, from solution.state.release.version
    origin_url: Option<String>,
    origin_commit: Option<String>,
    origin_hashes: Vec<HashRef>,
    relative: String,
}

fn find_and_parse_lock(
    ctx: &CatalogContext,
    toml_path: &Path,
) -> Result<HashMap<String, LockEntry>, CatalogError> {
    // Look for alire/alire.lock (preferred) or ./alire.lock alongside alire.toml.
    let lock_candidates: Vec<&PathBuf> = ctx.files_named("alire.lock").collect();

    for lock_path in lock_candidates {
        let rel = relative_path(&ctx.root, lock_path);
        match parse_alire_lock(lock_path, &rel) {
            Ok(entries) => {
                let mut map = HashMap::new();
                for e in entries {
                    let key = e.name.to_ascii_lowercase();
                    map.insert(key, e);
                }
                return Ok(map);
            }
            Err(_) => continue,
        }
    }

    // No lock found near toml_path — try explicit sibling paths.
    let toml_dir = toml_path.parent().unwrap_or(Path::new("."));
    for candidate in &[
        toml_dir.join("alire").join("alire.lock"),
        toml_dir.join("alire.lock"),
    ] {
        if candidate.exists() {
            let rel = relative_path(&ctx.root, candidate);
            if let Ok(entries) = parse_alire_lock(candidate, &rel) {
                let mut map = HashMap::new();
                for e in entries {
                    let key = e.name.to_ascii_lowercase();
                    map.insert(key, e);
                }
                return Ok(map);
            }
        }
    }

    Ok(HashMap::new())
}

fn parse_alire_lock(path: &Path, relative: &str) -> Result<Vec<LockEntry>, CatalogError> {
    let source = read_bounded(path)?;
    let root: toml::Value = toml::from_str(&source).map_err(|e| CatalogError::Malformed {
        kind: "alire.lock".to_owned(),
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;

    let mut out = Vec::new();

    // [[solution.state]] is a TOML array of tables.
    let states = root
        .get("solution")
        .and_then(|s| s.get("state"))
        .and_then(|v| v.as_array());

    let states = match states {
        Some(s) => s,
        None => return Ok(out),
    };

    for state in states {
        let crate_name = state
            .get("crate")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if crate_name.is_empty() {
            continue;
        }

        // Gate on `fulfilment`: only `solved`/`linked`/`hinted` describe a real
        // release. `missing` (and any unknown value) is NOT a resolved pin —
        // `versions` there is a constraint, never an exact version.
        let fulfilment = state
            .get("fulfilment")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let fulfilled = matches!(fulfilment, "solved" | "linked" | "hinted");
        if !fulfilled {
            continue;
        }

        // `release` nested table: version. Even a fulfilled state must carry a
        // real `release.version` to be Resolved.
        let release = state.get("release");
        let version = release
            .and_then(|r| r.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        if version.is_empty() {
            continue;
        }

        // `release.origin` nested table.
        let origin = release.and_then(|r| r.get("origin"));
        let origin_commit = origin
            .and_then(|o| o.get("commit"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());
        let origin_url = origin
            .and_then(|o| o.get("url"))
            .and_then(|v| v.as_str())
            .map(|s| {
                // Strip git+ prefix to get a clean vcs_url.
                s.strip_prefix("git+").unwrap_or(s).to_owned()
            });

        // origin.hashes: ["sha512:...", "sha256:..."]
        let origin_hashes = parse_origin_hashes(origin);

        out.push(LockEntry {
            name: crate_name,
            version,
            origin_url,
            origin_commit,
            origin_hashes,
            relative: relative.to_owned(),
        });
    }

    Ok(out)
}

fn parse_origin_hashes(origin: Option<&toml::Value>) -> Vec<HashRef> {
    let mut hashes = Vec::new();
    let Some(origin) = origin else { return hashes };
    let Some(arr) = origin.get("hashes").and_then(|v| v.as_array()) else {
        return hashes;
    };
    for item in arr {
        if let Some(s) = item.as_str() {
            // Format: "sha512:<hex>" or "sha256:<hex>".
            if let Some((alg, hex)) = s.split_once(':') {
                // Only derive the SHA-<bits> label AFTER confirming the prefix —
                // never byte-index (untrusted: alg may be <3 bytes or non-ASCII).
                let alg_label = if let Some(bits) = alg.strip_prefix("sha") {
                    format!("SHA-{bits}") // sha512 → SHA-512
                } else {
                    alg.to_ascii_uppercase()
                };
                if !hex.is_empty() {
                    hashes.push(HashRef {
                        alg: alg_label,
                        value_hex: hex.to_owned(),
                    });
                }
            }
        }
    }
    hashes
}

// ---------------------------------------------------------------------------
// Component builders
// ---------------------------------------------------------------------------

fn lock_entry_to_component(entry: &LockEntry) -> Component {
    let purl_val = build_alire_purl(
        &entry.name,
        &entry.version,
        entry.origin_url.as_deref(),
        entry.origin_commit.as_deref(),
    );
    let source = format!("{}:[[solution.state]] {}", entry.relative, entry.name);
    Component {
        component_ref: String::new(),
        name: entry.name.clone(),
        version: Some(entry.version.clone()),
        ecosystem: "alire".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(purl_val),
        cpe: None,
        sha256: None,
        hashes: entry.origin_hashes.clone(),
        identity_confidence: "high".to_owned(),
        matching_method: "alire_lock".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Resolved, source)],
        runtime_harnesses: Vec::new(),
    }
}

fn declared_component_stub(
    name: &str,
    _constraint: &str,
    _rel: &str,
    source: &str,
    lock_entry: &LockEntry,
) -> Component {
    let purl_val = build_alire_purl(
        name,
        &lock_entry.version,
        lock_entry.origin_url.as_deref(),
        lock_entry.origin_commit.as_deref(),
    );
    Component {
        component_ref: String::new(),
        name: name.to_owned(),
        version: Some(lock_entry.version.clone()),
        ecosystem: "alire".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(purl_val),
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "medium".to_owned(),
        matching_method: "alire_toml".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, source.to_owned())],
        runtime_harnesses: Vec::new(),
    }
}

fn declared_only_component(dep: &DeclaredDep, source: &str) -> Component {
    Component {
        component_ref: String::new(),
        name: dep.name.clone(),
        version: None, // constraint ≠ exact version
        ecosystem: "alire".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: None, // no exact version → no PURL
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "low".to_owned(),
        matching_method: "alire_toml".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, source.to_owned())],
        runtime_harnesses: Vec::new(),
    }
}

/// Build the Alire PURL. A git `origin.commit` is a VCS revision anchor — it is
/// folded into `vcs_url=git+<url>@<commit>` (NOT a `checksum=`). `checksum=` is
/// reserved for real `origin.hashes`, which travel in `hashes[]`, not the PURL.
fn build_alire_purl(name: &str, version: &str, url: Option<&str>, commit: Option<&str>) -> String {
    let base = purl::generic(name, version);
    let mut qualifiers: Vec<String> = Vec::new();
    match (url, commit) {
        (Some(u), Some(c)) => qualifiers.push(format!("vcs_url=git+{u}@{c}")),
        (Some(u), None) => qualifiers.push(format!("vcs_url={u}")),
        // A commit with no url (unusual) → record it as a revision anchor.
        (None, Some(c)) => qualifiers.push(format!("vcs_revision={c}")),
        (None, None) => {}
    }
    if qualifiers.is_empty() {
        base
    } else {
        format!("{}?{}", base, qualifiers.join("&"))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_bounded(path: &Path) -> Result<String, CatalogError> {
    let bytes = fs::read(path).map_err(|source| CatalogError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Ok(String::new());
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
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

    // -----------------------------------------------------------------------
    // alire.toml (Declared) parsing
    // -----------------------------------------------------------------------

    #[test]
    fn alire_toml_yields_declared_deps() {
        let ctx = fixture_ctx("alire");
        let out = AlireCataloger.catalog(&ctx).unwrap();
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        // libhello and ada_toml from [[depends-on]].
        assert!(
            names.contains(&"libhello"),
            "libhello must be declared: {:?}",
            names
        );
        assert!(
            names.contains(&"ada_toml"),
            "ada_toml must be declared: {:?}",
            names
        );
    }

    #[test]
    fn alire_toml_toolchain_crates_excluded() {
        let ctx = fixture_ctx("alire");
        let out = AlireCataloger.catalog(&ctx).unwrap();
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        assert!(!names.contains(&"gnat"), "gnat toolchain must be excluded");
        assert!(
            !names.contains(&"gprbuild"),
            "gprbuild toolchain must be excluded"
        );
    }

    // -----------------------------------------------------------------------
    // alire.lock (Resolved) parsing
    // -----------------------------------------------------------------------

    #[test]
    fn alire_lock_yields_resolved_components() {
        let ctx = fixture_ctx("alire");
        let out = AlireCataloger.catalog(&ctx).unwrap();
        let resolved: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "alire_lock")
            .collect();
        assert!(
            !resolved.is_empty(),
            "alire.lock must yield resolved components"
        );
        let names: Vec<_> = resolved.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"libhello"),
            "libhello must be resolved from lock"
        );
    }

    #[test]
    fn alire_lock_exact_version() {
        let ctx = fixture_ctx("alire");
        let out = AlireCataloger.catalog(&ctx).unwrap();
        let libhello = out
            .iter()
            .find(|c| c.matching_method == "alire_lock" && c.name == "libhello")
            .expect("libhello must be present in lock");
        assert_eq!(
            libhello.version.as_deref(),
            Some("1.0.1"),
            "version must match lock"
        );
    }

    #[test]
    fn alire_lock_resolved_evidence() {
        let ctx = fixture_ctx("alire");
        let out = AlireCataloger.catalog(&ctx).unwrap();
        for c in out.iter().filter(|c| c.matching_method == "alire_lock") {
            assert_eq!(
                top_rung(&c.evidence),
                Some(EvidenceKind::Resolved),
                "{} must be Resolved",
                c.name
            );
        }
    }

    #[test]
    fn alire_lock_git_commit_folded_into_vcs_url_not_checksum() {
        // NEW behavior (was `checksum=sha1:<commit>`): a git origin.commit is a VCS
        // anchor, not a content hash — it must be folded into vcs_url=git+<url>@<commit>
        // and `checksum=` reserved for real origin.hashes (none here).
        let ctx = fixture_ctx("alire");
        let out = AlireCataloger.catalog(&ctx).unwrap();
        let libhello = out
            .iter()
            .find(|c| c.matching_method == "alire_lock" && c.name == "libhello")
            .expect("libhello must be present");
        let purl = libhello.purl.as_deref().unwrap_or("");
        assert!(
            purl.contains(
                "vcs_url=git+https://github.com/alire-project/libhello.git@3c15bc7f3df22298077c9e96f178adc2829feb42"
            ),
            "commit must be folded into vcs_url: {purl}"
        );
        assert!(
            !purl.contains("checksum=sha1:"),
            "a git commit must NOT be emitted as checksum=sha1: {purl}"
        );
    }

    #[test]
    fn alire_lock_archive_origin_hashes_become_checksum() {
        // ada_toml has a real archive origin.hashes sha512 → that IS a checksum.
        let ctx = fixture_ctx("alire");
        let out = AlireCataloger.catalog(&ctx).unwrap();
        let ada_toml = out
            .iter()
            .find(|c| c.matching_method == "alire_lock" && c.name == "ada_toml")
            .expect("ada_toml must be present");
        assert_eq!(ada_toml.hashes.len(), 1);
        assert_eq!(ada_toml.hashes[0].alg, "SHA-512");
    }

    #[test]
    fn alire_purl_uses_generic_type() {
        let ctx = fixture_ctx("alire");
        let out = AlireCataloger.catalog(&ctx).unwrap();
        for c in &out {
            if let Some(purl) = &c.purl {
                assert!(
                    purl.starts_with("pkg:generic/"),
                    "must be pkg:generic: {purl}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Both depends-on syntaxes
    // -----------------------------------------------------------------------

    #[test]
    fn alire_toml_table_depends_on_syntax() {
        // The fixture uses [[depends-on]] table syntax.
        let ctx = fixture_ctx("alire");
        let out = AlireCataloger.catalog(&ctx).unwrap();
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        // ada_toml declared via [[depends-on]] table.
        assert!(
            names.contains(&"ada_toml"),
            "[[depends-on]] table syntax must be parsed: {:?}",
            names
        );
    }

    #[test]
    fn alire_toml_inline_array_crate_version_form() {
        // Inline `depends-on = [ {crate="x", version="^1.0"}, ... ]` (the
        // crate=/version= shape, distinct from the {name="constraint"} shape).
        let (_d, ctx) = temp_ctx(&[(
            "alire.toml",
            "name = \"app\"\nversion = \"0.1.0\"\n\
             depends-on = [ { crate = \"libfoo\", version = \"^1.0\" }, { crate = \"libbar\", version = \"~2.3\" } ]\n",
        )]);
        let out = AlireCataloger.catalog(&ctx).unwrap();
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"libfoo"),
            "libfoo from inline array: {names:?}"
        );
        assert!(
            names.contains(&"libbar"),
            "libbar from inline array: {names:?}"
        );
    }

    #[test]
    fn alire_toml_inline_array_name_constraint_form() {
        // The other inline shape: { name = "constraint" } where the key is the crate.
        let (_d, ctx) = temp_ctx(&[(
            "alire.toml",
            "name = \"app\"\nversion = \"0.1.0\"\n\
             depends-on = [ { libhello = \"^1.0\" } ]\n",
        )]);
        let out = AlireCataloger.catalog(&ctx).unwrap();
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"libhello"),
            "name=constraint form: {names:?}"
        );
    }

    #[test]
    fn alire_lock_unfulfilled_missing_state_not_resolved() {
        // A `[[solution.state]]` with fulfilment="missing" and no release.version
        // must NOT be emitted as a Resolved lock component.
        let (_d, ctx) = temp_ctx(&[
            (
                "alire.toml",
                "name = \"app\"\nversion = \"0.1.0\"\n[[depends-on]]\nmystery = \"^1.0\"\n",
            ),
            (
                "alire.lock",
                "[solution]\n[[solution.state]]\ncrate = \"mystery\"\nfulfilment = \"missing\"\nversions = \"^1.0\"\n",
            ),
        ]);
        let out = AlireCataloger.catalog(&ctx).unwrap();
        // No alire_lock (Resolved) component for mystery.
        assert!(
            !out.iter()
                .any(|c| c.matching_method == "alire_lock" && c.name == "mystery"),
            "missing-fulfilment state must not be Resolved"
        );
        // It is still Declared from alire.toml.
        assert!(
            out.iter()
                .any(|c| c.matching_method == "alire_toml" && c.name == "mystery"),
            "mystery still declared"
        );
    }

    #[test]
    fn alire_lock_linked_with_version_is_resolved() {
        // fulfilment="linked" WITH a real release.version → Resolved.
        let (_d, ctx) = temp_ctx(&[
            (
                "alire.toml",
                "name = \"app\"\nversion = \"0.1.0\"\n[[depends-on]]\nlinkedcrate = \"^2.0\"\n",
            ),
            (
                "alire.lock",
                "[solution]\n[[solution.state]]\ncrate = \"linkedcrate\"\nfulfilment = \"linked\"\n[solution.state.release]\nversion = \"2.1.0\"\n",
            ),
        ]);
        let out = AlireCataloger.catalog(&ctx).unwrap();
        let lc = out
            .iter()
            .find(|c| c.matching_method == "alire_lock" && c.name == "linkedcrate")
            .expect("linked-with-version must be Resolved");
        assert_eq!(lc.version.as_deref(), Some("2.1.0"));
    }

    // -----------------------------------------------------------------------
    // Merge via merge_by_identity
    // -----------------------------------------------------------------------

    #[test]
    fn alire_toml_and_lock_merge_to_one_component() {
        let ctx = fixture_ctx("alire");
        let raw = AlireCataloger.catalog(&ctx).unwrap();
        let merged = crate::merge_by_identity(raw);
        // libhello appears in both alire.toml and alire.lock.
        let libhello_entries: Vec<_> = merged
            .iter()
            .filter(|c| c.name == "libhello" && c.version.as_deref() == Some("1.0.1"))
            .collect();
        assert_eq!(
            libhello_entries.len(),
            1,
            "libhello must collapse to 1 component after merge"
        );
        // Must carry both Declared and Resolved evidence.
        let entry = &libhello_entries[0];
        assert!(
            entry
                .evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::Declared),
            "must have Declared evidence"
        );
        assert!(
            entry
                .evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::Resolved),
            "must have Resolved evidence"
        );
    }

    // -----------------------------------------------------------------------
    // detect
    // -----------------------------------------------------------------------

    #[test]
    fn detect_true_for_alire_toml() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/alire.toml".into()]);
        assert!(AlireCataloger.detect(&ctx));
    }

    #[test]
    fn detect_false_without_alire_files() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/Cargo.toml".into()]);
        assert!(!AlireCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // parse_origin_hashes unit test
    // -----------------------------------------------------------------------

    #[test]
    fn parse_origin_hashes_sha512() {
        let toml_str = r#"hashes = ["sha512:abc123def456"]"#;
        let val: toml::Value = toml::from_str(toml_str).unwrap();
        let hashes = parse_origin_hashes(Some(&val));
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].alg, "SHA-512");
        assert_eq!(hashes[0].value_hex, "abc123def456");
    }

    #[test]
    fn parse_origin_hashes_short_non_sha_prefix_does_not_panic() {
        // Untrusted input: a hash label shorter than 3 bytes / non-"sha" prefix
        // must NOT panic via `&alg[3..]` byte-indexing. (e.g. "x:abc", "md:..").
        let toml_str = r#"hashes = ["x:abc", "md:deadbeef"]"#;
        let val: toml::Value = toml::from_str(toml_str).unwrap();
        let hashes = parse_origin_hashes(Some(&val));
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0].alg, "X");
        assert_eq!(hashes[0].value_hex, "abc");
        assert_eq!(hashes[1].alg, "MD");
        assert_eq!(hashes[1].value_hex, "deadbeef");
    }

    #[test]
    fn parse_origin_hashes_non_ascii_prefix_does_not_panic() {
        // A multibyte first char (e.g. "é…") would make `&alg[3..]` slice mid-codepoint.
        let toml_str = "hashes = [\"\u{00e9}x:abc\"]";
        let val: toml::Value = toml::from_str(toml_str).unwrap();
        let hashes = parse_origin_hashes(Some(&val));
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].value_hex, "abc");
    }
}
