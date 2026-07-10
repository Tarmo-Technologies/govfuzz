// SPDX-License-Identifier: Apache-2.0

//! NuGet (.NET) ecosystem cataloger.
//!
//! **Declared**: `*.csproj` / `*.vbproj` / `*.fsproj` `<PackageReference>` (XML),
//! `packages.config` `<package>` (XML, exact pins), `Directory.Packages.props`
//! (Central Package Management — version lookup for csproj references that omit
//! `Version=`).
//!
//! **Resolved** (+hash): `packages.lock.json` (JSON).  Iterates every TFM bucket;
//! deduplicates by `name+resolved` version.  **Skips** `type=="Project"` (local
//! references).  `contentHash` = **base64 SHA-512** → decoded to hex and stored as
//! `HashRef{alg:"SHA-512", value_hex}`.
//!
//! # XML parsing
//! Targeted bounded string-scan: handles attribute order variations (`Include`
//! before or after `Version`), self-closing and child-element `<Version>` forms.
//! No external XML crate is added.
//!
//! # PURL
//! `pkg:nuget/<Name>@<Version>` — no namespace; name **case-preserved** (dotted
//! IDs like `Microsoft.Extensions.Logging` are one segment; case-insensitive
//! ecosystem but case is preserved per PURL spec recommendation).

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::{Component, HashRef};
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct NugetCataloger;

impl Cataloger for NugetCataloger {
    fn ecosystem(&self) -> &str {
        "nuget"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_ending_with(".csproj").next().is_some()
            || ctx.files_ending_with(".vbproj").next().is_some()
            || ctx.files_ending_with(".fsproj").next().is_some()
            || ctx.files_named("packages.config").next().is_some()
            || ctx.files_named("packages.lock.json").next().is_some()
            || ctx.files_named("Directory.Packages.props").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();

        // Build CPM index from Directory.Packages.props.
        let cpm_index = build_cpm_index(ctx)?;

        // Build name → LockEntry index from packages.lock.json.
        let mut lock_index: HashMap<String, LockEntry> = HashMap::new();
        for path in ctx.files_named("packages.lock.json") {
            let rel = relative_path(&ctx.root, path);
            for entry in parse_packages_lock(path, &rel)? {
                let key = entry.name.to_ascii_lowercase();
                lock_index.entry(key).or_insert_with(|| entry.clone());
                out.push(lock_entry_to_component(&entry));
            }
        }

        // .csproj / .vbproj / .fsproj: Declared lane.
        for proj_path in ctx
            .files_ending_with(".csproj")
            .chain(ctx.files_ending_with(".vbproj"))
            .chain(ctx.files_ending_with(".fsproj"))
        {
            let rel = relative_path(&ctx.root, proj_path);
            for dep in parse_project_file(proj_path, &rel)? {
                out.push(declared_component(dep, &lock_index, &cpm_index));
            }
        }

        // packages.config: exact pins (between Declared and Resolved).
        for path in ctx.files_named("packages.config") {
            let rel = relative_path(&ctx.root, path);
            for dep in parse_packages_config(path, &rel)? {
                out.push(packages_config_component(dep, &lock_index));
            }
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Internal data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LockEntry {
    name: String, // case-preserved
    version: String,
    content_hash_hex: Option<String>, // decoded from base64 SHA-512
    relative: String,
}

#[derive(Debug, Clone)]
struct DeclaredDep {
    name: String,
    /// None = absent (CPM) or range/floating (unresolvable offline).
    version: Option<String>,
    /// `<PrivateAssets>all</PrivateAssets>` / `developmentDependency="true"` →
    /// dev-only (build/test) scope, recorded as evidence.
    dev: bool,
    relative: String,
}

fn lock_entry_to_component(entry: &LockEntry) -> Component {
    let purl_val = purl::nuget(&entry.name, &entry.version);
    let hashes = entry
        .content_hash_hex
        .as_deref()
        .map(|hex| {
            vec![HashRef {
                alg: "SHA-512".to_owned(),
                value_hex: hex.to_owned(),
            }]
        })
        .unwrap_or_default();
    let source = format!("{}:{}", entry.relative, entry.name);
    Component {
        component_ref: String::new(),
        name: entry.name.clone(),
        version: Some(entry.version.clone()),
        ecosystem: "nuget".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(purl_val),
        cpe: None,
        sha256: None,
        hashes,
        identity_confidence: "high".to_owned(),
        matching_method: "packages_lock_json".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Resolved, source)],
        runtime_harnesses: Vec::new(),
    }
}

fn declared_component(
    dep: DeclaredDep,
    lock_index: &HashMap<String, LockEntry>,
    cpm_index: &HashMap<String, String>,
) -> Component {
    let source = format!("{}:{}", dep.relative, dep.name);

    // Resolve version: lockfile > CPM > declared attribute.
    let (resolved_version, purl_val) = {
        let key = dep.name.to_ascii_lowercase();
        if let Some(entry) = lock_index.get(&key) {
            (
                Some(entry.version.clone()),
                Some(purl::nuget(&dep.name, &entry.version)),
            )
        } else if dep.version.is_none() {
            // CPM lookup.
            let cpm_key = dep.name.to_ascii_lowercase();
            if let Some(cpm_ver) = cpm_index.get(&cpm_key) {
                (Some(cpm_ver.clone()), Some(purl::nuget(&dep.name, cpm_ver)))
            } else {
                (None, None)
            }
        } else {
            // Version from csproj attribute — may be a range; emit PURL only
            // for exact-looking versions.
            let v = dep.version.as_deref().unwrap_or("");
            if is_exact_nuget_version(v) {
                (dep.version.clone(), Some(purl::nuget(&dep.name, v)))
            } else {
                (dep.version.clone(), None)
            }
        }
    };

    Component {
        component_ref: String::new(),
        name: dep.name,
        version: resolved_version,
        ecosystem: "nuget".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "medium".to_owned(),
        matching_method: "csproj".to_owned(),
        evidence: declared_evidence(&source, dep.dev),
        runtime_harnesses: Vec::new(),
    }
}

/// Declared evidence for a NuGet dep, plus a `scope=dev` note when the dep is
/// dev-only (`<PrivateAssets>all</PrivateAssets>` / `developmentDependency`).
fn declared_evidence(source: &str, dev: bool) -> Vec<Evidence> {
    let mut ev = vec![Evidence::new(EvidenceKind::Declared, source.to_owned())];
    if dev {
        ev.push(Evidence {
            kind: EvidenceKind::Declared,
            source: format!("{source} scope=dev"),
            locator: Some("scope=dev".to_owned()),
        });
    }
    ev
}

fn packages_config_component(
    dep: DeclaredDep,
    lock_index: &HashMap<String, LockEntry>,
) -> Component {
    let source = format!("{}:{}", dep.relative, dep.name);
    let key = dep.name.to_ascii_lowercase();
    let (version, purl_val) = if let Some(entry) = lock_index.get(&key) {
        (
            Some(entry.version.clone()),
            Some(purl::nuget(&dep.name, &entry.version)),
        )
    } else if let Some(v) = &dep.version {
        (Some(v.clone()), Some(purl::nuget(&dep.name, v)))
    } else {
        (None, None)
    };

    Component {
        component_ref: String::new(),
        name: dep.name,
        version,
        ecosystem: "nuget".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "medium".to_owned(),
        matching_method: "packages_config".to_owned(),
        evidence: declared_evidence(&source, dep.dev),
        runtime_harnesses: Vec::new(),
    }
}

/// True if version looks like an exact pin (no `[`, `(`, `*`, floating).
fn is_exact_nuget_version(v: &str) -> bool {
    !v.contains('[') && !v.contains('(') && !v.contains('*') && !v.is_empty()
}

// ---------------------------------------------------------------------------
// packages.lock.json parser
// ---------------------------------------------------------------------------

fn parse_packages_lock(path: &Path, relative: &str) -> Result<Vec<LockEntry>, CatalogError> {
    let source = read_to_string(path)?;
    let root: serde_json::Value =
        serde_json::from_str(&source).map_err(|e| CatalogError::Malformed {
            kind: "packages.lock.json".to_owned(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;

    let Some(deps_map) = root.get("dependencies").and_then(|v| v.as_object()) else {
        return Ok(vec![]);
    };

    // Collect across all TFM buckets; dedup by lowercase name.
    let mut seen: HashMap<String, LockEntry> = HashMap::new();

    for (_tfm, packages) in deps_map {
        let Some(pkgs) = packages.as_object() else {
            continue;
        };
        for (pkg_name, info) in pkgs {
            // Skip type=="Project" (local project references).
            if info.get("type").and_then(|v| v.as_str()) == Some("Project") {
                continue;
            }
            let Some(resolved) = info.get("resolved").and_then(|v| v.as_str()) else {
                continue;
            };
            let content_hash_b64 = info
                .get("contentHash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let content_hash_hex = decode_base64_to_hex(content_hash_b64);

            let key = pkg_name.to_ascii_lowercase();
            seen.entry(key).or_insert_with(|| LockEntry {
                name: pkg_name.clone(), // case-preserved
                version: resolved.to_owned(),
                content_hash_hex,
                relative: relative.to_owned(),
            });
        }
    }

    Ok(seen.into_values().collect())
}

// ---------------------------------------------------------------------------
// .csproj / .vbproj / .fsproj parser (Declared)
// ---------------------------------------------------------------------------

fn parse_project_file(path: &Path, relative: &str) -> Result<Vec<DeclaredDep>, CatalogError> {
    let source = read_to_string(path)?;
    if source.len() > 4 * 1024 * 1024 {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut rest = source.as_str();
    while let Some(pr_start) = find_package_reference(rest) {
        let after = &rest[pr_start..];
        // Find the end of this element (self-closing `/>` or closing `</PackageReference>`).
        let elem_end = find_element_end(after);
        let elem = &after[..elem_end];

        let name = extract_xml_attr(elem, "Include");
        if let Some(name) = name {
            if !name.is_empty() && seen.insert(name.to_ascii_lowercase()) {
                // Version from attribute (may be absent for CPM).
                let version_attr = extract_xml_attr(elem, "Version")
                    .or_else(|| extract_xml_child_element(elem, "Version"));
                // Dev scope: <PrivateAssets>all</PrivateAssets> or PrivateAssets="all".
                let private_assets = extract_xml_child_element(elem, "PrivateAssets")
                    .or_else(|| extract_xml_attr(elem, "PrivateAssets"));
                let dev = private_assets
                    .as_deref()
                    .is_some_and(|v| v.eq_ignore_ascii_case("all"))
                    || extract_xml_attr(elem, "developmentDependency")
                        .as_deref()
                        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
                out.push(DeclaredDep {
                    name,
                    version: version_attr,
                    dev,
                    relative: relative.to_owned(),
                });
            }
        }
        rest = &after[elem_end..];
    }

    Ok(out)
}

/// Find the byte offset of the next `<PackageReference` in `text`.
fn find_package_reference(text: &str) -> Option<usize> {
    text.find("<PackageReference")
}

/// Find the end of the OUTER `<PackageReference …>` element starting at position 0.
///
/// First locate the end of the **opening tag** (its `>`). If that tag is itself
/// self-closing (`… />`), the element ends there. Otherwise it is a block element
/// and ends at its matching `</PackageReference>` — never at an inner child's
/// self-closing `/>` (e.g. `<PrivateAssets />` before `<Version>`).
fn find_element_end(text: &str) -> usize {
    // End of the opening tag: the first top-level `>`.
    let Some(gt) = text.find('>') else {
        return text.len();
    };
    // Self-closing opening tag? The char before `>` is `/` (ignoring whitespace).
    let opening = &text[..gt];
    if opening.trim_end().ends_with('/') {
        return gt + 1;
    }
    // Block element: end at the matching close tag, else fall back to the `>`.
    let close_tag = "</PackageReference>";
    match text.find(close_tag) {
        Some(p) => p + close_tag.len(),
        None => gt + 1,
    }
}

/// Extract an XML attribute value: `Name="value"` or `Name='value'`.
fn extract_xml_attr(elem: &str, attr_name: &str) -> Option<String> {
    // Try `attr_name="..."` and `attr_name='...'`.
    for quot in &['"', '\''] {
        let pattern = format!("{attr_name}={quot}");
        if let Some(start) = elem.find(&pattern) {
            let after = &elem[start + pattern.len()..];
            let end = after.find(*quot).unwrap_or(after.len());
            let val = after[..end].trim().to_owned();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// Extract a child element value: `<TagName>value</TagName>`.
fn extract_xml_child_element(elem: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = elem.find(&open)?;
    let after = &elem[start + open.len()..];
    let end = after.find(&close).unwrap_or(after.len());
    let val = after[..end].trim().to_owned();
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}

// ---------------------------------------------------------------------------
// packages.config parser
// ---------------------------------------------------------------------------

fn parse_packages_config(path: &Path, relative: &str) -> Result<Vec<DeclaredDep>, CatalogError> {
    let source = read_to_string(path)?;
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut rest = source.as_str();

    while let Some(start) = rest.find("<package ") {
        let after = &rest[start..];
        let end = after.find('>').unwrap_or(after.len());
        let elem = &after[..end + 1];

        let id = extract_xml_attr(elem, "id");
        let version = extract_xml_attr(elem, "version");
        let dev = extract_xml_attr(elem, "developmentDependency")
            .as_deref()
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));

        if let Some(name) = id {
            if !name.is_empty() && seen.insert(name.to_ascii_lowercase()) {
                out.push(DeclaredDep {
                    name,
                    version,
                    dev,
                    relative: relative.to_owned(),
                });
            }
        }
        rest = &after[end + 1..];
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Directory.Packages.props (Central Package Management)
// ---------------------------------------------------------------------------

/// Build a case-insensitive `name → version` index from `Directory.Packages.props`.
fn build_cpm_index(ctx: &CatalogContext) -> Result<HashMap<String, String>, CatalogError> {
    let mut index: HashMap<String, String> = HashMap::new();

    for path in ctx.files_named("Directory.Packages.props") {
        let source = read_to_string(path)?;
        let mut rest = source.as_str();

        // Find <PackageVersion Include="Name" Version="1.2.3" /> elements.
        while let Some(start) = rest.find("<PackageVersion") {
            let after = &rest[start..];
            let end = after.find('>').unwrap_or(after.len());
            let elem = &after[..end + 1];

            let name = extract_xml_attr(elem, "Include");
            let version = extract_xml_attr(elem, "Version");

            if let (Some(name), Some(ver)) = (name, version) {
                if !name.is_empty() && !ver.is_empty() {
                    index.insert(name.to_ascii_lowercase(), ver);
                }
            }
            rest = &after[end + 1..];
        }
    }

    Ok(index)
}

// ---------------------------------------------------------------------------
// base64 SHA-512 → hex decoder
// ---------------------------------------------------------------------------

/// Decode standard base64 (RFC 4648) to a hex string.
/// Returns `None` on malformed input; empty string input returns `None`.
pub(crate) fn decode_base64_to_hex(b64: &str) -> Option<String> {
    if b64.is_empty() {
        return None;
    }
    // Reuse the same table as the npm cataloger.
    // Slot for `=` (index 61) is \xff (invalid): a trailing `=` is stripped before
    // decoding, so an `=` reaching the table is an embedded/illegal char to reject.
    const TABLE: &[u8; 128] = b"\
        \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
        \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
        \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x3e\xff\xff\xff\x3f\
        \x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\xff\xff\xff\xff\xff\xff\
        \xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\
        \x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\
        \xff\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\
        \x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\xff\xff\xff\xff\xff";

    let b64_trimmed = b64.trim_end_matches('=');
    let mut bytes: Vec<u8> = Vec::with_capacity((b64_trimmed.len() * 3) / 4 + 1);
    let chars: Vec<u8> = b64_trimmed.bytes().collect();
    let mut i = 0;

    while i + 3 < chars.len() {
        let mut vals = [0u8; 4];
        for (j, &ch) in chars[i..i + 4].iter().enumerate() {
            if ch >= 128 {
                return None;
            }
            let v = TABLE[ch as usize];
            if v == 0xff {
                return None;
            }
            vals[j] = v;
        }
        bytes.push((vals[0] << 2) | (vals[1] >> 4));
        bytes.push((vals[1] << 4) | (vals[2] >> 2));
        bytes.push((vals[2] << 6) | vals[3]);
        i += 4;
    }

    let rem = chars.len() - i;
    // A lone remainder char (len % 4 == 1) is malformed base64 — reject it
    // instead of silently dropping it (which would store a truncated hash).
    if rem == 1 {
        return None;
    }
    if rem >= 2 {
        let get = |idx: usize| -> Option<u8> {
            let ch = *chars.get(idx)?;
            if ch >= 128 {
                return None;
            }
            let v = TABLE[ch as usize];
            if v == 0xff {
                None
            } else {
                Some(v)
            }
        };
        let v0 = get(i)?;
        let v1 = get(i + 1)?;
        bytes.push((v0 << 2) | (v1 >> 4));
        if rem == 3 {
            let v2 = get(i + 2)?;
            bytes.push((v1 << 4) | (v2 >> 2));
        }
    }

    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
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
    // base64 → hex decoder
    // -----------------------------------------------------------------------

    #[test]
    fn base64_decode_known_vector() {
        // "Man" = 0x4d 0x61 0x6e
        assert_eq!(decode_base64_to_hex("TWFu"), Some("4d616e".to_owned()));
    }

    #[test]
    fn base64_decode_sha512_content_hash() {
        // A valid 88-char base64-encoded SHA-512 (64 bytes → 88 base64 chars with padding).
        // This is the Serilog contentHash from the fixture.
        let b64 = "ZJYWvS1F91dM8TKO+9V5lfHKHqbsKvdSUew8VqSJMwFmteJ/WKZqX2vrnkgEdub+mFmjJq3ePiO85Vh7JD1jHQ==";
        let hex = decode_base64_to_hex(b64).unwrap();
        assert_eq!(
            hex.len(),
            128,
            "SHA-512 must decode to 64 bytes = 128 hex chars"
        );
    }

    #[test]
    fn base64_decode_empty_is_none() {
        assert!(decode_base64_to_hex("").is_none());
    }

    #[test]
    fn base64_decode_embedded_equals_rejected() {
        // An embedded mid-string `=` must be rejected (it is invalid base64
        // data), NOT decoded as 0x00 — otherwise we store a WRONG hash.
        assert_eq!(decode_base64_to_hex("TW=u"), None);
    }

    #[test]
    fn base64_decode_len_rem_one_rejected() {
        // A trailing single remainder char (len % 4 == 1) is malformed and must
        // be rejected, not silently dropped.
        assert_eq!(decode_base64_to_hex("TWFuQ"), None);
    }

    #[test]
    fn base64_decode_valid_sri_still_decodes() {
        // Regression guard: a valid base64 still decodes correctly after the fix.
        assert_eq!(decode_base64_to_hex("TWFu"), Some("4d616e".to_owned()));
        assert_eq!(decode_base64_to_hex("TWE="), Some("4d61".to_owned()));
    }

    // -----------------------------------------------------------------------
    // packages.lock.json parsing
    // -----------------------------------------------------------------------

    #[test]
    fn packages_lock_yields_resolved_components() {
        let ctx = fixture_ctx("nuget");
        let out = NugetCataloger.catalog(&ctx).unwrap();
        let lock_comps: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "packages_lock_json")
            .collect();
        assert!(
            !lock_comps.is_empty(),
            "packages.lock.json must yield components"
        );
        let names: Vec<_> = lock_comps.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"Newtonsoft.Json")
                || names.contains(&"newtonsoft.json")
                || names
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case("newtonsoft.json"))
        );
        assert!(names.iter().any(|n| n.eq_ignore_ascii_case("Serilog")));
    }

    #[test]
    fn packages_lock_project_type_skipped() {
        let ctx = fixture_ctx("nuget");
        let out = NugetCataloger.catalog(&ctx).unwrap();
        // MyApp.Shared has type=Project → must NOT appear.
        assert!(
            out.iter()
                .all(|c| !c.name.eq_ignore_ascii_case("MyApp.Shared")),
            "Project-type entries must be skipped"
        );
    }

    #[test]
    fn packages_lock_deduped_across_tfms() {
        let ctx = fixture_ctx("nuget");
        let out = NugetCataloger.catalog(&ctx).unwrap();
        // Newtonsoft.Json appears in both net8.0 and net8.0-windows → must appear once.
        let count = out
            .iter()
            .filter(|c| {
                c.matching_method == "packages_lock_json"
                    && c.name.eq_ignore_ascii_case("Newtonsoft.Json")
            })
            .count();
        assert_eq!(count, 1, "Newtonsoft.Json must be deduplicated across TFMs");
    }

    #[test]
    fn packages_lock_content_hash_decoded_to_sha512_hex() {
        let ctx = fixture_ctx("nuget");
        let out = NugetCataloger.catalog(&ctx).unwrap();
        let serilog = out
            .iter()
            .find(|c| {
                c.matching_method == "packages_lock_json" && c.name.eq_ignore_ascii_case("Serilog")
            })
            .expect("Serilog must be present");
        assert_eq!(serilog.hashes.len(), 1, "Serilog must have a hash");
        assert_eq!(serilog.hashes[0].alg, "SHA-512");
        assert_eq!(
            serilog.hashes[0].value_hex.len(),
            128,
            "SHA-512 must decode to 128 hex chars"
        );
    }

    #[test]
    fn packages_lock_purl_case_preserved() {
        let ctx = fixture_ctx("nuget");
        let out = NugetCataloger.catalog(&ctx).unwrap();
        // Find Serilog (declared with capital S).
        let serilog = out
            .iter()
            .find(|c| c.matching_method == "packages_lock_json" && c.name.contains("Serilog"))
            .expect("Serilog must be present");
        let purl = serilog.purl.as_deref().unwrap();
        assert!(purl.contains("Serilog"), "PURL must preserve case: {purl}");
        assert_eq!(purl, "pkg:nuget/Serilog@3.1.1", "PURL must match exactly");
    }

    #[test]
    fn packages_lock_evidence_is_resolved() {
        let ctx = fixture_ctx("nuget");
        let out = NugetCataloger.catalog(&ctx).unwrap();
        for c in out
            .iter()
            .filter(|c| c.matching_method == "packages_lock_json")
        {
            assert_eq!(
                top_rung(&c.evidence),
                Some(EvidenceKind::Resolved),
                "{} must be Resolved",
                c.name
            );
        }
    }

    // -----------------------------------------------------------------------
    // .csproj declared lane
    // -----------------------------------------------------------------------

    #[test]
    fn csproj_yields_declared_components() {
        let ctx = fixture_ctx("nuget");
        let out = NugetCataloger.catalog(&ctx).unwrap();
        let declared: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "csproj")
            .collect();
        assert!(
            !declared.is_empty(),
            "csproj must yield declared components"
        );
        let names: Vec<_> = declared.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names
                .iter()
                .any(|n| n.eq_ignore_ascii_case("Newtonsoft.Json")),
            "Newtonsoft.Json must be declared"
        );
        assert!(
            names.iter().any(|n| n.eq_ignore_ascii_case("Serilog")),
            "Serilog must be declared (CPM)"
        );
    }

    #[test]
    fn csproj_cpm_package_gets_version_from_props() {
        let ctx = fixture_ctx("nuget");
        let out = NugetCataloger.catalog(&ctx).unwrap();
        // Serilog has no Version= in csproj → resolved via Directory.Packages.props.
        // If packages.lock.json is present it takes precedence; otherwise CPM.
        let serilog_decl = out
            .iter()
            .find(|c| c.matching_method == "csproj" && c.name.eq_ignore_ascii_case("Serilog"))
            .expect("Serilog declared must be present");
        // Should have a version from either lock or CPM.
        assert!(
            serilog_decl.version.is_some(),
            "Serilog declared must have a resolved version"
        );
    }

    #[test]
    fn csproj_evidence_is_declared() {
        let ctx = fixture_ctx("nuget");
        let out = NugetCataloger.catalog(&ctx).unwrap();
        for c in out.iter().filter(|c| c.matching_method == "csproj") {
            assert_eq!(
                top_rung(&c.evidence),
                Some(EvidenceKind::Declared),
                "{} must be Declared",
                c.name
            );
        }
    }

    // -----------------------------------------------------------------------
    // packages.config exact pins
    // -----------------------------------------------------------------------

    #[test]
    fn packages_config_yields_declared_components() {
        let ctx = fixture_ctx("nuget");
        let out = NugetCataloger.catalog(&ctx).unwrap();
        let cfg_comps: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "packages_config")
            .collect();
        assert!(
            !cfg_comps.is_empty(),
            "packages.config must yield components"
        );
        let names: Vec<_> = cfg_comps.iter().map(|c| c.name.as_str()).collect();
        assert!(names.iter().any(|n| n.eq_ignore_ascii_case("NLog")));
        assert!(names.iter().any(|n| n.eq_ignore_ascii_case("Dapper")));
    }

    #[test]
    fn packages_config_purl_correct() {
        let ctx = fixture_ctx("nuget");
        let out = NugetCataloger.catalog(&ctx).unwrap();
        let nlog = out
            .iter()
            .find(|c| c.matching_method == "packages_config" && c.name == "NLog")
            .expect("NLog must be present in packages.config");
        assert_eq!(nlog.purl.as_deref(), Some("pkg:nuget/NLog@5.3.2"));
    }

    // -----------------------------------------------------------------------
    // merge_by_identity: csproj + lock collapse
    // -----------------------------------------------------------------------

    #[test]
    fn csproj_and_lock_merge_to_one_component() {
        let ctx = fixture_ctx("nuget");
        let raw = NugetCataloger.catalog(&ctx).unwrap();
        let merged = crate::merge_by_identity(raw);
        let serilog: Vec<_> = merged
            .iter()
            .filter(|c| c.purl.as_deref() == Some("pkg:nuget/Serilog@3.1.1"))
            .collect();
        assert_eq!(serilog.len(), 1, "Serilog must collapse to 1 component");
        assert!(serilog[0]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Declared));
        assert!(serilog[0]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Resolved));
    }

    // -----------------------------------------------------------------------
    // detect
    // -----------------------------------------------------------------------

    #[test]
    fn detect_true_for_csproj() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/MyApp.csproj".into()]);
        assert!(NugetCataloger.detect(&ctx));
    }

    #[test]
    fn detect_true_for_packages_lock() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/packages.lock.json".into()]);
        assert!(NugetCataloger.detect(&ctx));
    }

    #[test]
    fn detect_false_without_nuget_files() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/Cargo.toml".into()]);
        assert!(!NugetCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // XML attribute extractor helpers
    // -----------------------------------------------------------------------

    #[test]
    fn extract_xml_attr_double_quote() {
        let elem = r#"<PackageReference Include="Serilog" Version="3.1.1" />"#;
        assert_eq!(
            extract_xml_attr(elem, "Include"),
            Some("Serilog".to_owned())
        );
        assert_eq!(extract_xml_attr(elem, "Version"), Some("3.1.1".to_owned()));
    }

    #[test]
    fn extract_xml_attr_absent_returns_none() {
        let elem = r#"<PackageReference Include="Serilog" />"#;
        assert_eq!(extract_xml_attr(elem, "Version"), None);
    }

    #[test]
    fn extract_xml_child_element_version() {
        let elem =
            "<PackageReference Include=\"Foo\">\n  <Version>1.0.0</Version>\n</PackageReference>";
        assert_eq!(
            extract_xml_child_element(elem, "Version"),
            Some("1.0.0".to_owned())
        );
    }

    // -----------------------------------------------------------------------
    // block PackageReference with a self-closing child before <Version>
    // -----------------------------------------------------------------------

    #[test]
    fn find_element_end_self_closing_outer() {
        // A genuinely self-closing PackageReference ends at its own `/>`.
        let s = r#"<PackageReference Include="X" Version="1.0" /><PackageReference Include="Y" Version="2.0" />"#;
        let end = find_element_end(s);
        assert_eq!(
            &s[..end],
            r#"<PackageReference Include="X" Version="1.0" />"#
        );
    }

    #[test]
    fn find_element_end_block_with_self_closing_child() {
        // The OUTER element is a block; a self-closing child `<PrivateAssets />`
        // appears before `<Version>`. The end must be the OUTER close tag, not the
        // child's `/>`.
        let s = "<PackageReference Include=\"X\">\
                 <PrivateAssets />\
                 <Version>1.0</Version>\
                 </PackageReference>NEXT";
        let end = find_element_end(s);
        assert!(
            s[..end].contains("<Version>1.0</Version>"),
            "outer element must include the Version child: {:?}",
            &s[..end]
        );
        assert!(s[..end].ends_with("</PackageReference>"));
    }

    #[test]
    fn csproj_block_with_self_closing_child_keeps_version() {
        // Regression: a block <PackageReference> whose first child is self-closing
        // (<PrivateAssets />) before <Version> must still yield version 1.0.
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("App.csproj");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(
                b"<Project>\n<ItemGroup>\n\
                  <PackageReference Include=\"FancyPkg\">\n\
                    <PrivateAssets />\n\
                    <Version>1.0</Version>\n\
                  </PackageReference>\n\
                </ItemGroup>\n</Project>\n",
            )
            .unwrap();
        let ctx = CatalogContext::new(dir.path().to_path_buf(), vec![p]);
        let out = NugetCataloger.catalog(&ctx).unwrap();
        let pkg = out
            .iter()
            .find(|c| c.name == "FancyPkg")
            .expect("FancyPkg must be present");
        assert_eq!(
            pkg.version.as_deref(),
            Some("1.0"),
            "version must survive a self-closing child before <Version>"
        );
        assert_eq!(pkg.purl.as_deref(), Some("pkg:nuget/FancyPkg@1.0"));
    }

    #[test]
    fn csproj_private_assets_all_marked_dev() {
        // <PrivateAssets>all</PrivateAssets> marks a dev-scope dependency.
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("App.csproj");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(
                b"<Project>\n<ItemGroup>\n\
                  <PackageReference Include=\"BuildTool\" Version=\"2.0\">\n\
                    <PrivateAssets>all</PrivateAssets>\n\
                  </PackageReference>\n\
                </ItemGroup>\n</Project>\n",
            )
            .unwrap();
        let ctx = CatalogContext::new(dir.path().to_path_buf(), vec![p]);
        let out = NugetCataloger.catalog(&ctx).unwrap();
        let pkg = out
            .iter()
            .find(|c| c.name == "BuildTool")
            .expect("BuildTool must be present");
        let has_dev = pkg
            .evidence
            .iter()
            .any(|e| e.source.contains("scope=dev") || e.locator.as_deref() == Some("scope=dev"));
        assert!(has_dev, "PrivateAssets=all must be recorded as dev scope");
    }
}
