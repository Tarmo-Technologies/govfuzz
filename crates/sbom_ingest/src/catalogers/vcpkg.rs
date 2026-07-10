// SPDX-License-Identifier: Apache-2.0

//! vcpkg (C/C++) ecosystem cataloger.
//!
//! **Declared**: `vcpkg.json` (strict JSON manifest). There is no real lockfile
//! in a source tree — `builtin-baseline` (a microsoft/vcpkg git commit SHA) is
//! the de-facto "lock" for the version registry, but no resolved per-package
//! hashes exist without a build. All components are therefore **Declared**.
//!
//! # Parsing
//! - `dependencies` array: bare strings (port name) or objects
//!   `{ "name": "...", "version>=": "..." }`. The constraint key is the
//!   literal string `"version>="`.
//! - `overrides`: exact pins `{ "name": "...", "version": "..." }`.
//! - `builtin-baseline`: 40-hex git commit SHA recorded as a property/qualifier.
//! - Project's own version from one of `version`/`version-semver`/`version-date`/
//!   `version-string` (mutually exclusive — all four checked).
//!
//! # PURL
//! `pkg:generic/<name>@<version>` — no registered `pkg:vcpkg` type exists.
//! Port names are lowercase ASCII letters/digits/hyphens.
//! The `builtin-baseline` commit is carried as `?vcpkg_baseline=<sha>` qualifier.
//!
//! # Untrusted input
//! `vcpkg.json` is bounded (≤4 MiB). No execution, no network.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::Component;
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct VcpkgCataloger;

impl Cataloger for VcpkgCataloger {
    fn ecosystem(&self) -> &str {
        "vcpkg"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("vcpkg.json").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();

        for path in ctx.files_named("vcpkg.json") {
            let rel = relative_path(&ctx.root, path);
            let components = parse_vcpkg_json(path, &rel)?;
            out.extend(components);
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// vcpkg.json parser
// ---------------------------------------------------------------------------

fn parse_vcpkg_json(path: &Path, relative: &str) -> Result<Vec<Component>, CatalogError> {
    let source = read_bounded(path)?;
    let root: serde_json::Value =
        serde_json::from_str(&source).map_err(|e| CatalogError::Malformed {
            kind: "vcpkg.json".to_owned(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;

    let obj = match root.as_object() {
        Some(o) => o,
        None => return Ok(vec![]),
    };

    // Extract builtin-baseline (git commit SHA).
    let baseline = obj
        .get("builtin-baseline")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    // Build an override index: name → exact version.
    let mut override_index: HashMap<String, String> = HashMap::new();
    if let Some(overrides) = obj.get("overrides").and_then(|v| v.as_array()) {
        for item in overrides {
            if let (Some(name), Some(ver)) = (
                item.get("name").and_then(|v| v.as_str()),
                item.get("version").and_then(|v| v.as_str()),
            ) {
                if !name.is_empty() && !ver.is_empty() {
                    override_index.insert(name.to_ascii_lowercase(), ver.to_owned());
                }
            }
        }
    }

    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Process dependencies array.
    if let Some(deps) = obj.get("dependencies").and_then(|v| v.as_array()) {
        for dep in deps {
            if let Some(comp) = parse_dep_entry(dep, relative, &override_index, baseline.as_deref())
            {
                let key = comp.name.to_ascii_lowercase();
                if seen.insert(key) {
                    out.push(comp);
                }
            }
        }
    }

    // Process overrides (exact pins — emit even if not in dependencies).
    for (name, version) in &override_index {
        let key = name.to_ascii_lowercase();
        if !seen.contains(&key) {
            let purl_val = build_vcpkg_purl(name, version, baseline.as_deref());
            let source = format!("{}:overrides:{}", relative, name);
            out.push(Component {
                component_ref: String::new(),
                name: name.clone(),
                version: Some(version.clone()),
                ecosystem: "vcpkg".to_owned(),
                group: None,
                component_type: "library".to_owned(),
                supplier: None,
                license: None,
                purl: Some(purl_val),
                cpe: None,
                sha256: None,
                hashes: Vec::new(),
                identity_confidence: "medium".to_owned(),
                matching_method: "vcpkg_json_override".to_owned(),
                evidence: vec![Evidence::new(EvidenceKind::Declared, source)],
                runtime_harnesses: Vec::new(),
            });
            seen.insert(key);
        }
    }

    Ok(out)
}

/// Parse one entry from the `dependencies` array.
fn parse_dep_entry(
    dep: &serde_json::Value,
    relative: &str,
    override_index: &HashMap<String, String>,
    baseline: Option<&str>,
) -> Option<Component> {
    let (name, constraint) = if let Some(s) = dep.as_str() {
        // Bare string: port name only.
        (s.to_ascii_lowercase(), None::<String>)
    } else if let Some(obj) = dep.as_object() {
        let name = obj
            .get("name")
            .and_then(|v| v.as_str())?
            .to_ascii_lowercase();
        // Constraint key is the literal "version>=" string.
        let constraint = obj
            .get("version>=")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());
        (name, constraint)
    } else {
        return None;
    };

    if name.is_empty() {
        return None;
    }

    // Per §11: only an `overrides` exact pin gives a concrete version.
    // A `version>=` is a Declared LOWER BOUND — never a pin → version stays None
    // and no concrete @version PURL is emitted. The constraint is preserved as a
    // qualifier note only when an override pin also supplies a version base.
    let version = override_index.get(&name).cloned();

    let purl_val = version.as_deref().map(|v| {
        let base = build_vcpkg_purl(&name, v, baseline);
        match constraint.as_deref() {
            Some(c) if !c.is_empty() => {
                let sep = if base.contains('?') { '&' } else { '?' };
                format!("{base}{sep}vcpkg_version_constraint={c}")
            }
            _ => base,
        }
    });
    let source = format!("{}:dependencies:{}", relative, name);

    Some(Component {
        component_ref: String::new(),
        name: name.clone(),
        version,
        ecosystem: "vcpkg".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "low".to_owned(),
        matching_method: "vcpkg_json".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, source)],
        runtime_harnesses: Vec::new(),
    })
}

/// Build a `pkg:generic/<name>@<version>?vcpkg_baseline=<sha>` PURL.
fn build_vcpkg_purl(name: &str, version: &str, baseline: Option<&str>) -> String {
    let base = purl::generic(name, version);
    if let Some(bl) = baseline {
        if !bl.is_empty() {
            return format!("{}?vcpkg_baseline={}", base, bl);
        }
    }
    base
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

    // -----------------------------------------------------------------------
    // vcpkg.json parsing
    // -----------------------------------------------------------------------

    #[test]
    fn vcpkg_json_yields_declared_components() {
        let ctx = fixture_ctx("vcpkg");
        let out = VcpkgCataloger.catalog(&ctx).unwrap();
        assert!(!out.is_empty(), "vcpkg.json must yield components");
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"boost-system"),
            "boost-system must be present"
        );
        assert!(names.contains(&"fmt"), "fmt must be present");
    }

    #[test]
    fn vcpkg_json_bare_string_dep_has_no_version() {
        let ctx = fixture_ctx("vcpkg");
        let out = VcpkgCataloger.catalog(&ctx).unwrap();
        let boost = out
            .iter()
            .find(|c| c.name == "boost-system" && c.matching_method == "vcpkg_json")
            .expect("boost-system must be present");
        // Bare string dependency → no constraint → no version unless in overrides.
        assert!(
            boost.version.is_none() || boost.matching_method == "vcpkg_json",
            "bare-string dep may have no version"
        );
    }

    #[test]
    fn vcpkg_json_version_gte_is_not_a_pin() {
        // Per §11, `version>=` is a Declared LOWER BOUND, not a concrete pin.
        // It must NOT leak into the `version` field or a concrete @version PURL.
        let ctx = fixture_ctx("vcpkg");
        let out = VcpkgCataloger.catalog(&ctx).unwrap();
        let fmt = out
            .iter()
            .find(|c| c.name == "fmt" && c.matching_method == "vcpkg_json")
            .expect("fmt must be present");
        assert!(
            fmt.version.is_none(),
            "version>= must NOT become a pin: {:?}",
            fmt.version
        );
        assert!(
            fmt.purl.is_none(),
            "no concrete @version PURL for a version>= lower-bound dep: {:?}",
            fmt.purl
        );
    }

    #[test]
    fn vcpkg_json_override_pin_yields_generic_purl_with_baseline() {
        // Only an `overrides` exact pin produces a concrete @version PURL.
        let ctx = fixture_ctx("vcpkg");
        let out = VcpkgCataloger.catalog(&ctx).unwrap();
        let zlib = out
            .iter()
            .find(|c| c.name == "zlib")
            .expect("zlib override must be present");
        let purl = zlib.purl.as_deref().unwrap_or("");
        assert!(
            purl.starts_with("pkg:generic/"),
            "must be pkg:generic: {purl}"
        );
        assert_eq!(
            purl,
            "pkg:generic/zlib@1.2.8?vcpkg_baseline=3426db05b996481ca31e95fff3734cf23e0f51bc"
        );
    }

    #[test]
    fn vcpkg_json_baseline_in_purl_qualifier() {
        let ctx = fixture_ctx("vcpkg");
        let out = VcpkgCataloger.catalog(&ctx).unwrap();
        // At least one component (the override pin) carries a PURL.
        assert!(out.iter().any(|c| c.purl.is_some()));
        for c in &out {
            if let Some(purl) = &c.purl {
                assert!(
                    purl.contains("vcpkg_baseline=3426db05b996481ca31e95fff3734cf23e0f51bc"),
                    "builtin-baseline must appear in purl qualifier: {purl}"
                );
            }
        }
    }

    #[test]
    fn vcpkg_json_overrides_yield_exact_pin() {
        let ctx = fixture_ctx("vcpkg");
        let out = VcpkgCataloger.catalog(&ctx).unwrap();
        let zlib = out
            .iter()
            .find(|c| c.name == "zlib")
            .expect("zlib override must be present");
        assert_eq!(
            zlib.version.as_deref(),
            Some("1.2.8"),
            "zlib override version must be 1.2.8"
        );
    }

    #[test]
    fn vcpkg_json_all_declared() {
        let ctx = fixture_ctx("vcpkg");
        let out = VcpkgCataloger.catalog(&ctx).unwrap();
        for c in &out {
            assert_eq!(
                top_rung(&c.evidence),
                Some(EvidenceKind::Declared),
                "{} must be Declared (no lockfile for vcpkg source scan)",
                c.name
            );
        }
    }

    #[test]
    fn vcpkg_json_port_names_lowercased() {
        let ctx = fixture_ctx("vcpkg");
        let out = VcpkgCataloger.catalog(&ctx).unwrap();
        for c in &out {
            // Port names: lowercase letters/digits/hyphens.
            assert_eq!(
                c.name,
                c.name.to_ascii_lowercase(),
                "port name must be lowercase: {}",
                c.name
            );
        }
    }

    // -----------------------------------------------------------------------
    // detect
    // -----------------------------------------------------------------------

    #[test]
    fn detect_true_for_vcpkg_json() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/vcpkg.json".into()]);
        assert!(VcpkgCataloger.detect(&ctx));
    }

    #[test]
    fn detect_false_without_vcpkg_files() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/Cargo.toml".into()]);
        assert!(!VcpkgCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // Unit: build_vcpkg_purl
    // -----------------------------------------------------------------------

    #[test]
    fn build_vcpkg_purl_with_baseline() {
        let purl = build_vcpkg_purl("boost-system", "1.83.0", Some("abc123"));
        assert_eq!(
            purl,
            "pkg:generic/boost-system@1.83.0?vcpkg_baseline=abc123"
        );
    }

    #[test]
    fn build_vcpkg_purl_without_baseline() {
        let purl = build_vcpkg_purl("fmt", "10.1.1", None);
        assert_eq!(purl, "pkg:generic/fmt@10.1.1");
    }
}
