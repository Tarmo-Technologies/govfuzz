// SPDX-License-Identifier: Apache-2.0

//! Tier-A native-manifest catalogers: Cargo, npm, declared `*.json`, and
//! directory `VERSION` files. Ported verbatim from `governance`'s original
//! file-discovery functions so Phase-1 output is byte-identical.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::Component;
use crate::evidence::{Evidence, EvidenceKind};
use serde_json::Value;
use std::fs;
use std::path::Path;

/// All built-in native-manifest catalogers, in deterministic order.
pub fn all() -> Vec<Box<dyn Cataloger>> {
    vec![
        Box::new(CargoCataloger),
        Box::new(NpmCataloger),
        Box::new(DeclaredCataloger),
        Box::new(VersionFileCataloger),
    ]
}

pub struct CargoCataloger;

impl Cataloger for CargoCataloger {
    fn ecosystem(&self) -> &str {
        "cargo"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("Cargo.toml").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();
        for path in ctx.files_named("Cargo.toml") {
            let relative = relative_path(&ctx.root, path);
            if let Some(component) = cargo_component(path, &relative)? {
                out.push(component);
            }
        }
        Ok(out)
    }
}

pub struct NpmCataloger;

impl Cataloger for NpmCataloger {
    fn ecosystem(&self) -> &str {
        "npm"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("package.json").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();
        for path in ctx.files_named("package.json") {
            let relative = relative_path(&ctx.root, path);
            if let Some(component) = npm_component(path, &relative)? {
                out.push(component);
            }
        }
        Ok(out)
    }
}

pub struct DeclaredCataloger;

impl Cataloger for DeclaredCataloger {
    fn ecosystem(&self) -> &str {
        "declared"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("govfuzz-component.json").next().is_some()
            || ctx.files_named("component.json").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();
        for path in ctx
            .files_named("govfuzz-component.json")
            .chain(ctx.files_named("component.json"))
        {
            let relative = relative_path(&ctx.root, path);
            if let Some(component) = declared_component(path, &relative)? {
                out.push(component);
            }
        }
        Ok(out)
    }
}

pub struct VersionFileCataloger;

impl Cataloger for VersionFileCataloger {
    fn ecosystem(&self) -> &str {
        "generic"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("VERSION").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();
        for path in ctx.files_named("VERSION") {
            let relative = relative_path(&ctx.root, path);
            if let Some(component) = version_file_component(path, &relative)? {
                out.push(component);
            }
        }
        Ok(out)
    }
}

fn cargo_component(path: &Path, relative: &str) -> Result<Option<Component>, CatalogError> {
    let source = read_to_string(path)?;
    let Some(name) = simple_toml_field(&source, "name") else {
        return Ok(None);
    };
    let version = simple_toml_field(&source, "version");
    Ok(Some(Component {
        component_ref: String::new(),
        name: name.clone(),
        version: version.clone(),
        ecosystem: "cargo".to_owned(),
        group: None,
        component_type: "source".to_owned(),
        supplier: None,
        license: simple_toml_field(&source, "license"),
        purl: version
            .as_ref()
            .map(|version| format!("pkg:cargo/{name}@{version}")),
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "high".to_owned(),
        matching_method: "cargo_manifest".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, relative.to_owned())],
        runtime_harnesses: Vec::new(),
    }))
}

fn npm_component(path: &Path, relative: &str) -> Result<Option<Component>, CatalogError> {
    let value = read_json(path)?;
    let Some(name) = value.get("name").and_then(Value::as_str).map(str::to_owned) else {
        return Ok(None);
    };
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(Some(Component {
        component_ref: String::new(),
        name: name.clone(),
        version: version.clone(),
        ecosystem: "npm".to_owned(),
        group: None,
        component_type: "source".to_owned(),
        supplier: json_string_or_name(value.get("author")),
        license: value
            .get("license")
            .and_then(Value::as_str)
            .map(str::to_owned),
        purl: version
            .as_ref()
            .map(|version| crate::purl::npm(&name, version)),
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "high".to_owned(),
        matching_method: "package_json".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, relative.to_owned())],
        runtime_harnesses: Vec::new(),
    }))
}

fn declared_component(path: &Path, relative: &str) -> Result<Option<Component>, CatalogError> {
    let value = read_json(path)?;
    let Some(name) = value.get("name").and_then(Value::as_str).map(str::to_owned) else {
        return Ok(None);
    };
    let ecosystem = value
        .get("ecosystem")
        .and_then(Value::as_str)
        .unwrap_or("generic")
        .to_owned();
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let cpe = value
        .get("cpe")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|cpe| !cpe.is_empty())
        .map(str::to_owned);
    Ok(Some(Component {
        component_ref: String::new(),
        name: name.clone(),
        version: version.clone(),
        ecosystem: ecosystem.clone(),
        group: None,
        component_type: value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("vendored")
            .to_owned(),
        supplier: json_string_or_name(value.get("supplier")),
        license: value
            .get("license")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|license| !license.is_empty())
            .map(str::to_owned),
        purl: version
            .as_ref()
            .map(|version| format!("pkg:{ecosystem}/{name}@{version}")),
        cpe,
        sha256: value
            .get("sha256")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|sha256| !sha256.is_empty())
            .map(str::to_owned),
        hashes: Vec::new(),
        identity_confidence: "high".to_owned(),
        matching_method: "declared_component".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, relative.to_owned())],
        runtime_harnesses: Vec::new(),
    }))
}

fn version_file_component(path: &Path, relative: &str) -> Result<Option<Component>, CatalogError> {
    let Some(parent_name) = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
    else {
        return Ok(None);
    };
    let Some((name, version_from_dir)) = split_name_version(parent_name) else {
        return Ok(None);
    };
    let version = read_to_string(path)?
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .or_else(|| Some(version_from_dir.clone()));
    Ok(Some(Component {
        component_ref: String::new(),
        name,
        version,
        ecosystem: "generic".to_owned(),
        group: None,
        component_type: "vendored".to_owned(),
        supplier: None,
        license: None,
        purl: None,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "low".to_owned(),
        matching_method: "directory_version".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, relative.to_owned())],
        runtime_harnesses: Vec::new(),
    }))
}

// --- helpers (ported verbatim from `governance`) ---

fn read_to_string(path: &Path) -> Result<String, CatalogError> {
    fs::read_to_string(path).map_err(|source| CatalogError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_json(path: &Path) -> Result<Value, CatalogError> {
    let bytes = fs::read(path).map_err(|source| CatalogError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| CatalogError::Malformed {
        kind: "json".to_owned(),
        path: path.to_path_buf(),
        detail: source.to_string(),
    })
}

fn json_string_or_name(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn simple_toml_field(source: &str, field: &str) -> Option<String> {
    source.lines().find_map(|line| {
        let trimmed = line.trim();
        let (key, value) = trimmed.split_once('=')?;
        if key.trim() == field {
            Some(toml_scalar_value(value))
        } else {
            None
        }
    })
}

/// Extract a scalar TOML value from the right-hand side of a `key = value` line.
/// A quoted string (`"x"` or `'x'`) is taken up to its matching close quote, so
/// a trailing inline `# comment` is dropped; a bare value is cut at the first
/// `#`. Without this, a `version = "1.4.0"  #:version` line (rust-csv's
/// workspace members) parsed to `1.4.0"  #:version` — a corrupt version and an
/// invalid `pkg:cargo/<name>@1.4.0"  #:version` PURL.
fn toml_scalar_value(raw: &str) -> String {
    let value = raw.trim();
    if let Some(quote @ ('"' | '\'')) = value.chars().next() {
        if let Some(end) = value[1..].find(quote) {
            return value[1..1 + end].to_owned();
        }
    }
    value.split('#').next().unwrap_or(value).trim().to_owned()
}

fn split_name_version(value: &str) -> Option<(String, String)> {
    let (name, version) = value.rsplit_once('-')?;
    if name.is_empty() || !version.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some((name.to_owned(), version.to_owned()))
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(path_string)
        .unwrap_or_else(|_| path_string(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn ctx_for(root: &Path) -> CatalogContext {
        let mut files = Vec::new();
        collect(root, &mut files);
        files.sort();
        CatalogContext::new(root.to_path_buf(), files)
    }

    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                collect(&path, out);
            } else {
                out.push(path);
            }
        }
    }

    #[test]
    fn cargo_cataloger_emits_declared_evidence_with_relative_path() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("crate")).unwrap();
        fs::write(
            dir.path().join("crate/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nlicense = \"MIT\"\n",
        )
        .unwrap();
        let ctx = ctx_for(dir.path());
        assert!(CargoCataloger.detect(&ctx));
        let out = CargoCataloger.catalog(&ctx).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "demo");
        assert_eq!(out[0].version.as_deref(), Some("0.1.0"));
        assert_eq!(out[0].purl.as_deref(), Some("pkg:cargo/demo@0.1.0"));
        assert_eq!(out[0].evidence_summary(), "crate/Cargo.toml");
        assert_eq!(out[0].evidence[0].kind, EvidenceKind::Declared);
    }

    #[test]
    fn cargo_cataloger_strips_trailing_inline_comment_from_version() {
        // Regression: rust-csv's workspace members declare `version = "1.4.0"
        // #:version`. The line parser kept the closing quote and the comment,
        // emitting version `1.4.0"  #:version` and an invalid
        // `pkg:cargo/csv@1.4.0"  #:version` PURL. The quoted value must be taken
        // up to the closing quote, dropping the inline comment.
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("csv")).unwrap();
        fs::write(
            dir.path().join("csv/Cargo.toml"),
            "[package]\nname = \"csv\"  # crate name\nversion = \"1.4.0\"  #:version\nlicense = \"Unlicense OR MIT\"\n",
        )
        .unwrap();
        let ctx = ctx_for(dir.path());
        let out = CargoCataloger.catalog(&ctx).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "csv");
        assert_eq!(out[0].version.as_deref(), Some("1.4.0"));
        assert_eq!(out[0].purl.as_deref(), Some("pkg:cargo/csv@1.4.0"));
        assert_eq!(out[0].license.as_deref(), Some("Unlicense OR MIT"));
    }

    #[test]
    fn npm_cataloger_reads_package_json() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            "{\"name\":\"ui\",\"version\":\"2.0.0\",\"license\":\"MIT\"}",
        )
        .unwrap();
        let ctx = ctx_for(dir.path());
        let out = NpmCataloger.catalog(&ctx).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].purl.as_deref(), Some("pkg:npm/ui@2.0.0"));
        assert_eq!(out[0].evidence_summary(), "package.json");
    }

    #[test]
    fn declared_cataloger_handles_both_filenames() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("govfuzz-component.json"),
            "{\"name\":\"libfoo\",\"ecosystem\":\"deb\",\"version\":\"3.1\"}",
        )
        .unwrap();
        let ctx = ctx_for(dir.path());
        assert!(DeclaredCataloger.detect(&ctx));
        let out = DeclaredCataloger.catalog(&ctx).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].purl.as_deref(), Some("pkg:deb/libfoo@3.1"));
    }

    #[test]
    fn version_file_cataloger_uses_directory_name() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("vendor/zlib-1.3.1")).unwrap();
        fs::write(dir.path().join("vendor/zlib-1.3.1/VERSION"), "1.3.1\n").unwrap();
        let ctx = ctx_for(dir.path());
        let out = VersionFileCataloger.catalog(&ctx).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "zlib");
        assert_eq!(out[0].version.as_deref(), Some("1.3.1"));
        assert_eq!(out[0].evidence_summary(), "vendor/zlib-1.3.1/VERSION");
    }

    #[test]
    fn malformed_json_is_a_catalog_error() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{not json").unwrap();
        let ctx = ctx_for(dir.path());
        let err = NpmCataloger.catalog(&ctx).unwrap_err();
        assert!(matches!(err, CatalogError::Malformed { .. }));
    }

    #[test]
    fn scoped_npm_package_purl_encodes_at_sign() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            "{\"name\":\"@acme/widget\",\"version\":\"1.2.3\"}",
        )
        .unwrap();
        let ctx = ctx_for(dir.path());
        let out = NpmCataloger.catalog(&ctx).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "@acme/widget");
        assert_eq!(out[0].purl.as_deref(), Some("pkg:npm/%40acme/widget@1.2.3"));
    }
}
