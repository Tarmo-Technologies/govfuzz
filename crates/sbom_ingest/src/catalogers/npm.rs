// SPDX-License-Identifier: Apache-2.0

//! npm / Yarn / pnpm ecosystem cataloger.
//!
//! **Declared**: `package.json` `dependencies`/`devDependencies`/
//! `optionalDependencies`/`peerDependencies` (ranges → PURL only when lockfile
//! pin found; project-self key `""` is left to `native_manifest::NpmCataloger`).
//!
//! **Resolved**: `package-lock.json` / `npm-shrinkwrap.json` (prefer flat
//! `packages` map; v2/v3), `yarn.lock` (classic v1 and Berry v2+),
//! `pnpm-lock.yaml` (string `lockfileVersion`).
//!
//! # SRI hash decoding
//! npm/yarn-classic/pnpm carry `sha512-<base64>` (or legacy `sha1-<base64>`).
//! These are decoded to hex and stored as `HashRef{alg:"SHA-512"|"SHA-1", ...}`.
//! Yarn Berry `10c0/<hex>` checksums are NOT SRI — stored as an evidence note
//! only, not a `HashRef`.
//!
//! # PURL
//! `pkg:npm/<name>@<version>`; scoped `@scope/name` → `pkg:npm/%40scope/name@..`.
//! Case is preserved (spec: names are case-sensitive, do NOT force-lowercase).
//!
//! # What is NOT emitted
//! The project-self entry (key `""`) is skipped — `native_manifest::NpmCataloger`
//! already handles it. `link:true` and `workspace:` entries are also skipped.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::{Component, HashRef};
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct NpmLockCataloger;

impl Cataloger for NpmLockCataloger {
    fn ecosystem(&self) -> &str {
        "npm"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("package-lock.json").next().is_some()
            || ctx.files_named("npm-shrinkwrap.json").next().is_some()
            || ctx.files_named("yarn.lock").next().is_some()
            || ctx.files_named("pnpm-lock.yaml").next().is_some()
            || ctx.files_named("package.json").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();

        // Collect (pin, method) pairs from every lockfile, then dedup by
        // (name, version, integrity) with a seen-set — the v1 tree lists the same
        // pkg at many (non-adjacent) depths, and a name can appear at >1 version.
        let mut pins: Vec<(LockPin, &'static str)> = Vec::new();

        // npm-shrinkwrap.json takes precedence over package-lock.json.
        let have_shrinkwrap = ctx.files_named("npm-shrinkwrap.json").next().is_some();

        if have_shrinkwrap {
            for path in ctx.files_named("npm-shrinkwrap.json") {
                let rel = relative_path(&ctx.root, path);
                for pin in parse_npm_lock(path, &rel)? {
                    pins.push((pin, "npm_shrinkwrap"));
                }
            }
        } else {
            for path in ctx.files_named("package-lock.json") {
                let rel = relative_path(&ctx.root, path);
                for pin in parse_npm_lock(path, &rel)? {
                    pins.push((pin, "package_lock"));
                }
            }
        }

        for path in ctx.files_named("yarn.lock") {
            let rel = relative_path(&ctx.root, path);
            for pin in parse_yarn_lock(path, &rel)? {
                pins.push((pin, "yarn_lock"));
            }
        }

        for path in ctx.files_named("pnpm-lock.yaml") {
            let rel = relative_path(&ctx.root, path);
            for pin in parse_pnpm_lock(path, &rel)? {
                pins.push((pin, "pnpm_lock"));
            }
        }

        // Build a name → LockPin index for declared→resolved joining, preferring a
        // depth-0 `node_modules/<name>` entry over a deeply-nested one. Also dedup
        // emitted components by (name, version, integrity).
        let mut lock_index: HashMap<String, LockPin> = HashMap::new();
        let mut seen: std::collections::HashSet<(String, String, String)> =
            std::collections::HashSet::new();

        for (pin, method) in pins {
            // Prefer a depth-0 entry in the index; otherwise the first seen wins.
            match lock_index.get(&pin.name) {
                Some(existing) if existing.depth <= pin.depth => {}
                _ => {
                    lock_index.insert(pin.name.clone(), pin.clone());
                }
            }

            let key = (pin.name.clone(), pin.version.clone(), integrity_token(&pin));
            if seen.insert(key) {
                out.push(lock_pin_to_component(pin, method));
            }
        }

        // package.json: Declared lane (ranges → no PURL unless in lockfile).
        // Emit DEPENDENCIES ONLY — the project-self is left to native_manifest.
        for path in ctx.files_named("package.json") {
            let rel = relative_path(&ctx.root, path);
            for entry in parse_package_json_deps(path, &rel)? {
                out.push(declared_component(entry, &lock_index));
            }
        }

        Ok(out)
    }
}

/// A stable integrity token for dedup keying: the joined `alg:hex` of every
/// HashRef, plus any Yarn Berry checksum. Empty when no integrity is known.
fn integrity_token(pin: &LockPin) -> String {
    let mut parts: Vec<String> = pin
        .hashes
        .iter()
        .map(|h| format!("{}:{}", h.alg, h.value_hex))
        .collect();
    if let Some(ck) = &pin.berry_checksum {
        parts.push(ck.clone());
    }
    parts.join(",")
}

// ---------------------------------------------------------------------------
// Internal data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LockPin {
    name: String,
    version: String,
    hashes: Vec<HashRef>,
    /// Yarn Berry checksum (opaque, not a HashRef) — stored as evidence note.
    berry_checksum: Option<String>,
    /// Install-path nesting depth (0 = top-level `node_modules/<name>`). Used to
    /// prefer a depth-0 entry when joining a declared dep to its resolved pin.
    /// Lockfile formats without a path (yarn/pnpm) default to 0.
    depth: usize,
    relative: String,
}

#[derive(Debug, Clone)]
struct DeclaredDep {
    name: String,
    /// The raw `package.json` version spec (range, exact pin, tag, git/url, …).
    spec: String,
    relative: String,
}

fn lock_pin_to_component(pin: LockPin, method: &str) -> Component {
    let purl_val = purl::npm(&pin.name, &pin.version);
    let source = format!("{}:{}", pin.relative, pin.name);
    let mut evidence = vec![Evidence::new(EvidenceKind::Resolved, source)];
    if let Some(ck) = pin.berry_checksum {
        evidence.push(Evidence {
            kind: EvidenceKind::Resolved,
            source: format!("{}:{} (berry-checksum)", pin.relative, pin.name),
            locator: Some(ck),
        });
    }
    Component {
        component_ref: String::new(),
        name: pin.name,
        version: Some(pin.version),
        ecosystem: "npm".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(purl_val),
        cpe: None,
        sha256: None,
        hashes: pin.hashes,
        identity_confidence: "high".to_owned(),
        matching_method: method.to_owned(),
        evidence,
        runtime_harnesses: Vec::new(),
    }
}

fn declared_component(dep: DeclaredDep, lock_index: &HashMap<String, LockPin>) -> Component {
    let source = format!("{}:{}", dep.relative, dep.name);
    // When the lockfile pins this dep, carry BOTH the versioned PURL and the
    // matching `version` field (a versioned PURL with `version: None` is
    // inconsistent and breaks identity/merge).
    let (version, purl_val) = if let Some(pin) = lock_index.get(&dep.name) {
        (
            Some(pin.version.clone()),
            Some(purl::npm(&dep.name, &pin.version)),
        )
    } else if is_exact_npm_version(&dep.spec) {
        // No lockfile pin, but the spec is itself an EXACT version (`"4.17.21"`).
        // Treat it as the resolved version so the component is not version-less.
        // True ranges (`^`, `~`, `1.x`, …) and non-registry specs stay version-less.
        let exact = dep.spec.trim().to_owned();
        let purl = purl::npm(&dep.name, &exact);
        (Some(exact), Some(purl))
    } else {
        (None, None)
    };
    Component {
        component_ref: String::new(),
        name: dep.name,
        version,
        ecosystem: "npm".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "medium".to_owned(),
        matching_method: "package_json".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, source)],
        runtime_harnesses: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// package.json parser (Declared lane — deps only, not self)
// ---------------------------------------------------------------------------

fn parse_package_json_deps(path: &Path, relative: &str) -> Result<Vec<DeclaredDep>, CatalogError> {
    let source = read_to_string(path)?;
    let root: serde_json::Value =
        serde_json::from_str(&source).map_err(|e| CatalogError::Malformed {
            kind: "package.json".to_owned(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;

    let mut out = Vec::new();
    for section in &[
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(map) = root.get(*section).and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, spec) in map {
            if name.is_empty() {
                continue;
            }
            out.push(DeclaredDep {
                name: name.clone(),
                spec: spec.as_str().unwrap_or("").to_owned(),
                relative: relative.to_owned(),
            });
        }
    }

    // Dedup by name across sections with a seen-set (not adjacency: the same dep
    // can appear in non-consecutive sections, e.g. dependencies + peerDependencies).
    let mut seen = std::collections::HashSet::new();
    out.retain(|d| seen.insert(d.name.clone()));
    Ok(out)
}

// ---------------------------------------------------------------------------
// package-lock.json / npm-shrinkwrap.json parser
// ---------------------------------------------------------------------------

fn parse_npm_lock(path: &Path, relative: &str) -> Result<Vec<LockPin>, CatalogError> {
    let source = read_to_string(path)?;
    let root: serde_json::Value =
        serde_json::from_str(&source).map_err(|e| CatalogError::Malformed {
            kind: "package-lock.json".to_owned(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;

    let lock_ver = root
        .get("lockfileVersion")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    let mut out = Vec::new();

    // Prefer flat `packages` map (v2/v3).
    if lock_ver >= 2 {
        if let Some(packages) = root.get("packages").and_then(|v| v.as_object()) {
            for (key, pkg) in packages {
                // Skip root entry.
                if key.is_empty() {
                    continue;
                }
                // Skip link entries.
                if pkg.get("link").and_then(|v| v.as_bool()).unwrap_or(false) {
                    continue;
                }
                // Derive name from the install path: trailing node_modules/<name>
                // or node_modules/@scope/name.
                let name = if let Some(n) = pkg.get("name").and_then(|v| v.as_str()) {
                    n.to_owned()
                } else {
                    name_from_install_path(key)
                };
                if name.is_empty() {
                    continue;
                }
                let Some(version) = pkg.get("version").and_then(|v| v.as_str()) else {
                    continue;
                };
                // Skip workspace local entries (version is often "0.0.0-use.local").
                if version == "0.0.0-use.local" {
                    continue;
                }
                let integrity = pkg.get("integrity").and_then(|v| v.as_str()).unwrap_or("");
                let hashes = decode_sri_integrity(integrity);
                out.push(LockPin {
                    name,
                    version: version.to_owned(),
                    hashes,
                    berry_checksum: None,
                    depth: install_path_depth(key),
                    relative: relative.to_owned(),
                });
            }
            return Ok(out);
        }
    }

    // v1: walk recursive `dependencies` tree.
    if let Some(deps) = root.get("dependencies").and_then(|v| v.as_object()) {
        collect_v1_deps(deps, relative, 0, &mut out);
    }

    Ok(out)
}

/// Nesting depth of an npm install-path key: 0 for `node_modules/<name>`, 1 for
/// `node_modules/a/node_modules/<name>`, etc. = (count of `node_modules/`) - 1.
fn install_path_depth(key: &str) -> usize {
    key.matches("node_modules/").count().saturating_sub(1)
}

fn collect_v1_deps(
    deps: &serde_json::Map<String, serde_json::Value>,
    relative: &str,
    depth: usize,
    out: &mut Vec<LockPin>,
) {
    for (name, pkg) in deps {
        if let Some(version) = pkg.get("version").and_then(|v| v.as_str()) {
            if version == "0.0.0-use.local" {
                continue;
            }
            let integrity = pkg.get("integrity").and_then(|v| v.as_str()).unwrap_or("");
            let hashes = decode_sri_integrity(integrity);
            out.push(LockPin {
                name: name.clone(),
                version: version.to_owned(),
                hashes,
                berry_checksum: None,
                depth,
                relative: relative.to_owned(),
            });
        }
        // Recurse into nested `dependencies`.
        if let Some(nested) = pkg.get("dependencies").and_then(|v| v.as_object()) {
            collect_v1_deps(nested, relative, depth + 1, out);
        }
    }
}

/// Extract name from an npm install path like `node_modules/@scope/pkg` or
/// `node_modules/lodash`. Returns empty string on parse failure.
fn name_from_install_path(key: &str) -> String {
    // Find the last `node_modules/` segment.
    if let Some(pos) = key.rfind("node_modules/") {
        let after = &key[pos + "node_modules/".len()..];
        // Scoped: starts with `@`, consume two segments.
        if after.starts_with('@') {
            // Keep as `@scope/name`.
            return after.to_owned();
        }
        // Unscoped: everything up to the next `/` (or all of it).
        return after.to_owned();
    }
    String::new()
}

// ---------------------------------------------------------------------------
// yarn.lock parser (classic v1 and Berry v2+)
// ---------------------------------------------------------------------------

fn parse_yarn_lock(path: &Path, relative: &str) -> Result<Vec<LockPin>, CatalogError> {
    let source = read_to_string(path)?;
    // Berry detection: presence of `__metadata:` at the top level.
    let is_berry = source
        .lines()
        .take(50)
        .any(|l| l.trim_start() == "__metadata:" || l.trim_start().starts_with("__metadata:"));
    if is_berry {
        parse_yarn_berry(&source, relative)
    } else {
        parse_yarn_classic(&source, relative)
    }
}

/// Parse Yarn classic v1 lock (custom YAML-ish, NOT valid YAML).
/// Block: comma-sep quoted descriptors on one line, body indented with `  `.
fn parse_yarn_classic(source: &str, relative: &str) -> Result<Vec<LockPin>, CatalogError> {
    let mut out = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_integrity: Option<String> = None;

    let flush = |name: &Option<String>,
                 version: &Option<String>,
                 integrity: &Option<String>,
                 out: &mut Vec<LockPin>| {
        if let (Some(n), Some(v)) = (name, version) {
            let hashes = integrity
                .as_deref()
                .map(decode_sri_integrity)
                .unwrap_or_default();
            out.push(LockPin {
                name: n.clone(),
                version: v.clone(),
                hashes,
                berry_checksum: None,
                depth: 0,
                relative: relative.to_owned(),
            });
        }
    };

    for line in source.lines() {
        // Skip comments and empty lines.
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        // Yarn metadata header marker.
        if line.starts_with("__metadata:") {
            continue;
        }

        // A block header line: not indented, ends with `:`.
        if !line.starts_with(' ') && !line.starts_with('\t') && line.ends_with(':') {
            // Flush the previous block.
            flush(
                &current_name,
                &current_version,
                &current_integrity,
                &mut out,
            );
            current_version = None;
            current_integrity = None;

            // Parse name: take the FIRST descriptor, split on last `@` to get name.
            // Descriptors are comma-sep quoted strings like `"lodash@^4.0.0", "lodash@^4.1.0":`.
            let header = line.trim_end_matches(':');
            // Take the first descriptor.
            let first_descriptor = header
                .split(',')
                .next()
                .unwrap_or(header)
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            current_name = Some(name_from_yarn_descriptor(first_descriptor));
        } else if line.starts_with("  ") || line.starts_with('\t') {
            // Body lines.
            let trimmed = line.trim();
            if let Some(ver) = trimmed.strip_prefix("version ") {
                current_version = Some(ver.trim().trim_matches('"').to_owned());
            } else if let Some(int) = trimmed.strip_prefix("integrity ") {
                current_integrity = Some(int.trim().to_owned());
            }
        }
    }
    // Flush last block.
    flush(
        &current_name,
        &current_version,
        &current_integrity,
        &mut out,
    );

    Ok(out)
}

/// Split a Yarn descriptor on the LAST `@` to recover the name.
/// `lodash@^4.0.0` → `lodash`; `@babel/core@^7.0.0` → `@babel/core`.
fn name_from_yarn_descriptor(descriptor: &str) -> String {
    // Find the last `@` that is not the very first character.
    let start = if descriptor.starts_with('@') { 1 } else { 0 };
    if let Some(pos) = descriptor[start..].rfind('@') {
        descriptor[..start + pos].to_owned()
    } else {
        descriptor.to_owned()
    }
}

/// Parse Yarn Berry (v2+) lockfile (real YAML-ish; has `__metadata`).
/// Uses resolution field: `"@babel/core@npm:7.8.3"` → name + version.
fn parse_yarn_berry(source: &str, relative: &str) -> Result<Vec<LockPin>, CatalogError> {
    let mut out = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_checksum: Option<String> = None;
    let mut in_metadata = false;

    let flush = |name: &Option<String>,
                 version: &Option<String>,
                 checksum: &Option<String>,
                 out: &mut Vec<LockPin>| {
        if let (Some(n), Some(v)) = (name, version) {
            if !n.is_empty() && !v.is_empty() {
                out.push(LockPin {
                    name: n.clone(),
                    version: v.clone(),
                    hashes: Vec::new(), // Berry checksum is not SRI
                    berry_checksum: checksum.clone(),
                    depth: 0,
                    relative: relative.to_owned(),
                });
            }
        }
    };

    for line in source.lines() {
        // Skip __metadata block.
        if line.trim() == "__metadata:" {
            in_metadata = true;
            continue;
        }
        if in_metadata {
            if line.is_empty() {
                in_metadata = false;
            }
            continue;
        }

        if line.trim().is_empty() || line.starts_with('#') {
            if current_name.is_some() {
                flush(&current_name, &current_version, &current_checksum, &mut out);
                current_name = None;
                current_version = None;
                current_checksum = None;
            }
            continue;
        }

        // Block header: not indented (or `"@scope...":`).
        if !line.starts_with(' ') && !line.starts_with('\t') && line.ends_with(':') {
            flush(&current_name, &current_version, &current_checksum, &mut out);
            current_version = None;
            current_checksum = None;
            // Extract name from first descriptor.
            let header = line.trim_end_matches(':').trim().trim_matches('"');
            let first = header
                .split(',')
                .next()
                .unwrap_or(header)
                .trim()
                .trim_matches('"');
            // Only npm: protocol entries are registry packages.
            if first.contains("@npm:") || first.contains("npm:") {
                current_name = Some(name_from_yarn_descriptor(first));
            } else {
                current_name = None;
            }
        } else {
            let trimmed = line.trim();
            if let Some(ver) = trimmed.strip_prefix("version: ") {
                current_version = Some(ver.trim().trim_matches('"').to_owned());
            } else if let Some(res) = trimmed.strip_prefix("resolution: ") {
                // resolution: "name@npm:version" — parse the npm: version.
                let res = res.trim().trim_matches('"');
                if let Some(npm_ver) = extract_npm_resolution_version(res) {
                    // Also extract name from resolution.
                    if current_name.is_none() {
                        let name_part = res.split("@npm:").next().unwrap_or("").trim_matches('"');
                        if !name_part.is_empty() {
                            current_name = Some(name_part.to_owned());
                        }
                    }
                    current_version = Some(npm_ver);
                }
            } else if let Some(ck) = trimmed.strip_prefix("checksum: ") {
                current_checksum = Some(ck.trim().trim_matches('"').to_owned());
            }
        }
    }
    flush(&current_name, &current_version, &current_checksum, &mut out);

    Ok(out)
}

/// Extract the bare version from `name@npm:version` resolution strings.
fn extract_npm_resolution_version(resolution: &str) -> Option<String> {
    // Find `@npm:` and take what's after.
    if let Some(pos) = resolution.find("@npm:") {
        let ver = &resolution[pos + "@npm:".len()..];
        // Strip any trailing `#hash` fragment.
        let ver = ver.split('#').next().unwrap_or(ver);
        if !ver.is_empty() {
            return Some(ver.to_owned());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml parser
// ---------------------------------------------------------------------------

fn parse_pnpm_lock(path: &Path, relative: &str) -> Result<Vec<LockPin>, CatalogError> {
    let source = read_to_string(path)?;
    // lockfileVersion is a STRING in pnpm (e.g. '5.4', '6.0', '9.0').
    // We parse it as plain text rather than YAML to avoid YAML dependency.
    let mut out = Vec::new();
    let mut in_packages = false;
    let mut current_key: Option<String> = None;
    let mut current_integrity: Option<String> = None;

    let flush = |key: &Option<String>, integrity: &Option<String>, out: &mut Vec<LockPin>| {
        if let Some(k) = key {
            if let Some((name, version)) = parse_pnpm_key(k) {
                let hashes = integrity
                    .as_deref()
                    .map(decode_sri_integrity)
                    .unwrap_or_default();
                out.push(LockPin {
                    name,
                    version,
                    hashes,
                    berry_checksum: None,
                    depth: 0,
                    relative: relative.to_owned(),
                });
            }
        }
    };

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Section header detection.
        if line.starts_with("packages:") {
            in_packages = true;
            continue;
        }
        // Another top-level section resets packages mode.
        if !line.starts_with(' ') && !line.starts_with('\t') && line.ends_with(':') {
            if in_packages && line != "packages:" {
                flush(&current_key, &current_integrity, &mut out);
                current_key = None;
                current_integrity = None;
            }
            in_packages = line.starts_with("packages:");
            continue;
        }

        if !in_packages {
            continue;
        }

        // A package entry key: 2-space indented, ends with `:`.
        // v5: `/name/version`, v6: `/name@version`, v9: `name@version`.
        if line.starts_with("  ") && !line.starts_with("    ") && trimmed.ends_with(':') {
            flush(&current_key, &current_integrity, &mut out);
            current_integrity = None;
            let key = trimmed
                .trim_end_matches(':')
                .trim_matches('\'')
                .trim_matches('"');
            current_key = Some(key.to_owned());
        } else if line.starts_with("    ") {
            // 4-space body fields.
            if let Some(int) = trimmed.strip_prefix("integrity: ") {
                current_integrity = Some(int.trim().to_owned());
            }
        }
    }
    flush(&current_key, &current_integrity, &mut out);

    Ok(out)
}

/// Parse a pnpm package key into (name, version).
/// v5: `/name/version` or `/name/version_peers`
/// v6: `/name@version` or `/@scope/name@version`
/// v9: `name@version` or `@scope/name@version`
/// All may have `(peer@ver...)` suffixes — strip them.
fn parse_pnpm_key(key: &str) -> Option<(String, String)> {
    // Strip leading `/` (v5/v6).
    let key = key.strip_prefix('/').unwrap_or(key);
    // Strip `(peer...)` parenthetical suffixes.
    let key = if let Some(pos) = key.find('(') {
        key[..pos].trim()
    } else {
        key
    };
    if key.is_empty() {
        return None;
    }

    // Split on LAST `@` (but not the scope `@`).
    let start = if key.starts_with('@') { 1 } else { 0 };
    if let Some(at_pos) = key[start..].rfind('@') {
        let name = key[..start + at_pos].to_owned();
        let version_part = &key[start + at_pos + 1..];
        // v5 uses `/` as the version separator — check for that.
        // For v5 `/lodash/4.17.21`, after stripping leading `/`, key is `lodash/4.17.21`.
        // The name/version split above would put `lodash` as name if we split on last `/`.
        // But if no `@` found, fall back to `/` split.
        if !name.is_empty() && !version_part.is_empty() {
            return Some((name, version_part.to_owned()));
        }
    }

    // v5 fallback: split on last `/`.
    if let Some(pos) = key.rfind('/') {
        let name = key[..pos].to_owned();
        let version = key[pos + 1..].to_owned();
        if !name.is_empty() && !version.is_empty() {
            return Some((name, version));
        }
    }

    None
}

// ---------------------------------------------------------------------------
// SRI integrity decoder
// ---------------------------------------------------------------------------

/// Decode a W3C SRI integrity string `sha512-<base64>` or `sha1-<base64>` into
/// a `HashRef`. Returns empty vec for unknown/malformed/Berry checksums.
fn decode_sri_integrity(integrity: &str) -> Vec<HashRef> {
    if integrity.is_empty() {
        return Vec::new();
    }
    let (alg_label, b64) = if let Some(rest) = integrity.strip_prefix("sha512-") {
        ("SHA-512", rest)
    } else if let Some(rest) = integrity.strip_prefix("sha1-") {
        ("SHA-1", rest)
    } else if let Some(rest) = integrity.strip_prefix("sha256-") {
        ("SHA-256", rest)
    } else {
        // Not SRI (e.g. Berry checksum `10c0/...`).
        return Vec::new();
    };

    match base64_decode_to_hex(b64) {
        Some(hex) => vec![HashRef {
            alg: alg_label.to_owned(),
            value_hex: hex,
        }],
        None => Vec::new(),
    }
}

/// Minimal RFC 4648 standard base64 decoder → hex string.
/// Accepts `+` and `/` (standard) and `=` padding. Returns None on malformed input.
fn base64_decode_to_hex(b64: &str) -> Option<String> {
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

    let b64 = b64.trim_end_matches('=');
    let mut bytes = Vec::with_capacity((b64.len() * 3) / 4 + 1);
    let chars: Vec<u8> = b64.bytes().collect();
    let mut i = 0;
    while i + 3 < chars.len() {
        let c = [chars[i], chars[i + 1], chars[i + 2], chars[i + 3]];
        let mut vals = [0u8; 4];
        for (j, &ch) in c.iter().enumerate() {
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
    // Handle remaining 2 or 3 chars.
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

/// True iff a `package.json` spec is an EXACT registry version (`"4.17.21"`,
/// `"1.0.0-beta.1"`) rather than a range or non-registry reference. Rejects the
/// range operators `^ ~ > < = * |`, whitespace/hyphen ranges, dist-tags
/// (`latest`), wildcard cores (`1.x`), and protocol/path specs (git/file/url/
/// `workspace:`/`npm:`/`github:user/repo`). Without a lockfile, an exact spec is
/// the resolved version; a range correctly stays version-less.
fn is_exact_npm_version(spec: &str) -> bool {
    let s = spec.trim();
    if s.is_empty() {
        return false;
    }
    // Protocol / path specs: `git+…`, `file:…`, `http(s):…`, `link:…`,
    // `workspace:…`, `npm:…`, `github:user/repo`, `user/repo`.
    if s.contains(':') || s.contains('/') {
        return false;
    }
    // Range operators, unions, and whitespace/hyphen ranges.
    if s.contains(['^', '~', '>', '<', '=', '*', '|', ' ']) {
        return false;
    }
    // Dist-tags (`latest`, `next`) and git shas do not start with a digit.
    if !s.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    // The version core (before a `-` prerelease / `+` build tag) must be all
    // digits and dots — this rejects wildcard cores like `1.x` / `1.2.X` while
    // still allowing a prerelease tag that happens to contain letters.
    let core = s.split(['-', '+']).next().unwrap_or(s);
    core.chars().all(|c| c.is_ascii_digit() || c == '.')
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
    // base64 decoder
    // -----------------------------------------------------------------------

    #[test]
    fn base64_decode_known_vector() {
        // "Man" → 77 61 6e
        let hex = base64_decode_to_hex("TWFu").unwrap();
        assert_eq!(hex, "4d616e");
    }

    #[test]
    fn base64_decode_with_padding() {
        // "Ma" → 4d 61
        let hex = base64_decode_to_hex("TWE=").unwrap();
        assert_eq!(hex, "4d61");
    }

    #[test]
    fn base64_decode_embedded_equals_rejected() {
        // An embedded mid-string `=` must be rejected, NOT decoded as 0x00 —
        // otherwise an SRI hash is stored WRONG but labeled SHA-512.
        assert_eq!(base64_decode_to_hex("TW=u"), None);
    }

    #[test]
    fn base64_decode_len_rem_one_rejected() {
        // A trailing single remainder char (len % 4 == 1) is malformed.
        assert_eq!(base64_decode_to_hex("TWFuQ"), None);
    }

    // -----------------------------------------------------------------------
    // SRI decode
    // -----------------------------------------------------------------------

    #[test]
    fn sri_sha512_decodes_to_hash_ref() {
        // A real 64-byte payload encoded as sha512-<base64>.
        let hex = base64_decode_to_hex(
            "a9gxpmdXtZEInkCSHUJDLHZVBgb1QS0jhss4cPP93EW7s+uC5bikET2twEF3KV+7rDblJcmNvTR7VJejqd2C2g=="
        ).unwrap();
        assert_eq!(hex.len(), 128); // 64 bytes
        let hashes = decode_sri_integrity(&format!("sha512-{}", "a9gxpmdXtZEInkCSHUJDLHZVBgb1QS0jhss4cPP93EW7s+uC5bikET2twEF3KV+7rDblJcmNvTR7VJejqd2C2g=="));
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].alg, "SHA-512");
        assert_eq!(hashes[0].value_hex.len(), 128);
    }

    #[test]
    fn berry_checksum_not_decoded_as_sri() {
        let hashes = decode_sri_integrity("10c0/abcdef1234");
        assert!(hashes.is_empty(), "Berry checksum must not decode as SRI");
    }

    // -----------------------------------------------------------------------
    // package-lock.json v3 parsing
    // -----------------------------------------------------------------------

    #[test]
    fn package_lock_v3_yields_resolved_components() {
        let ctx = fixture_ctx("npm");
        let out = NpmLockCataloger.catalog(&ctx).unwrap();
        let lock_comps: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "package_lock")
            .collect();
        let names: Vec<_> = lock_comps.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"lodash"), "lodash must be present");
        assert!(
            names.contains(&"@babel/code-frame"),
            "@babel/code-frame must be present"
        );
    }

    #[test]
    fn package_lock_root_entry_skipped() {
        let ctx = fixture_ctx("npm");
        let out = NpmLockCataloger.catalog(&ctx).unwrap();
        // The root `""` entry must not emit a component.
        assert!(
            out.iter().all(|c| c.name != "demo-app"),
            "root self-entry must be excluded"
        );
    }

    #[test]
    fn package_lock_purl_unscoped() {
        let ctx = fixture_ctx("npm");
        let out = NpmLockCataloger.catalog(&ctx).unwrap();
        let lodash = out
            .iter()
            .find(|c| c.name == "lodash" && c.matching_method == "package_lock")
            .unwrap();
        assert_eq!(lodash.version.as_deref(), Some("4.17.21"));
        assert_eq!(lodash.purl.as_deref(), Some("pkg:npm/lodash@4.17.21"));
    }

    #[test]
    fn package_lock_purl_scoped_encodes_at() {
        let ctx = fixture_ctx("npm");
        let out = NpmLockCataloger.catalog(&ctx).unwrap();
        let babel = out
            .iter()
            .find(|c| c.name == "@babel/code-frame" && c.matching_method == "package_lock")
            .unwrap();
        assert_eq!(babel.version.as_deref(), Some("7.8.3"));
        assert_eq!(
            babel.purl.as_deref(),
            Some("pkg:npm/%40babel/code-frame@7.8.3")
        );
    }

    #[test]
    fn package_lock_integrity_decoded_to_hash_ref() {
        let ctx = fixture_ctx("npm");
        let out = NpmLockCataloger.catalog(&ctx).unwrap();
        let lodash = out
            .iter()
            .find(|c| c.name == "lodash" && c.matching_method == "package_lock")
            .unwrap();
        assert_eq!(lodash.hashes.len(), 1);
        assert_eq!(lodash.hashes[0].alg, "SHA-512");
        assert_eq!(lodash.hashes[0].value_hex.len(), 128);
    }

    #[test]
    fn package_lock_evidence_is_resolved() {
        let ctx = fixture_ctx("npm");
        let out = NpmLockCataloger.catalog(&ctx).unwrap();
        let lodash = out
            .iter()
            .find(|c| c.name == "lodash" && c.matching_method == "package_lock")
            .unwrap();
        assert_eq!(top_rung(&lodash.evidence), Some(EvidenceKind::Resolved));
    }

    // -----------------------------------------------------------------------
    // package.json declared (no deps in fixture → no declared comps)
    // -----------------------------------------------------------------------

    #[test]
    fn package_json_with_no_deps_emits_nothing_declared() {
        let ctx = fixture_ctx("npm");
        let out = NpmLockCataloger.catalog(&ctx).unwrap();
        let declared: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "package_json")
            .collect();
        // Our demo fixture has empty dependencies → 0 declared comps.
        assert!(
            declared.is_empty(),
            "no deps in package.json → no declared components"
        );
    }

    // -----------------------------------------------------------------------
    // Helper unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn name_from_install_path_unscoped() {
        assert_eq!(name_from_install_path("node_modules/lodash"), "lodash");
    }

    #[test]
    fn name_from_install_path_scoped() {
        assert_eq!(
            name_from_install_path("node_modules/@babel/code-frame"),
            "@babel/code-frame"
        );
    }

    #[test]
    fn name_from_yarn_descriptor_unscoped() {
        assert_eq!(name_from_yarn_descriptor("lodash@^4.0.0"), "lodash");
    }

    #[test]
    fn name_from_yarn_descriptor_scoped() {
        assert_eq!(
            name_from_yarn_descriptor("@babel/core@^7.0.0"),
            "@babel/core"
        );
    }

    #[test]
    fn parse_pnpm_key_v9_unscoped() {
        let (name, ver) = parse_pnpm_key("lodash@4.17.21").unwrap();
        assert_eq!(name, "lodash");
        assert_eq!(ver, "4.17.21");
    }

    #[test]
    fn parse_pnpm_key_v9_scoped() {
        let (name, ver) = parse_pnpm_key("@babel/core@7.0.0").unwrap();
        assert_eq!(name, "@babel/core");
        assert_eq!(ver, "7.0.0");
    }

    #[test]
    fn parse_pnpm_key_strips_peer_suffix() {
        let (name, ver) = parse_pnpm_key("@babel/core@7.0.0(peer@1.0.0)").unwrap();
        assert_eq!(name, "@babel/core");
        assert_eq!(ver, "7.0.0");
    }

    // -----------------------------------------------------------------------
    // same pkg at two versions; non-adjacent dedup
    // -----------------------------------------------------------------------

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
    fn same_package_two_versions_both_emitted_once() {
        // A v3 lock with lodash at two install paths / two versions. Both must be
        // emitted, each exactly once.
        let lock = "{\"lockfileVersion\":3,\"packages\":{\
            \"\":{\"name\":\"app\"},\
            \"node_modules/lodash\":{\"version\":\"4.17.21\",\"integrity\":\"sha512-a9gxpmdXtZEInkCSHUJDLHZVBgb1QS0jhss4cPP93EW7s+uC5bikET2twEF3KV+7rDblJcmNvTR7VJejqd2C2g==\"},\
            \"node_modules/dep/node_modules/lodash\":{\"version\":\"3.10.1\",\"integrity\":\"sha1-W/Rm8oG1uc/sg9PVPbReWtkdoKw=\"}\
        }}";
        let (_d, ctx) = temp_ctx(&[("package-lock.json", lock)]);
        let out = NpmLockCataloger.catalog(&ctx).unwrap();
        let v4: Vec<_> = out
            .iter()
            .filter(|c| c.name == "lodash" && c.version.as_deref() == Some("4.17.21"))
            .collect();
        let v3: Vec<_> = out
            .iter()
            .filter(|c| c.name == "lodash" && c.version.as_deref() == Some("3.10.1"))
            .collect();
        assert_eq!(v4.len(), 1, "lodash@4.17.21 once");
        assert_eq!(v3.len(), 1, "lodash@3.10.1 once");
    }

    #[test]
    fn v1_tree_non_adjacent_duplicate_removed() {
        // A v1 recursive tree lists lodash@4.17.21 at the top AND nested under
        // another (non-adjacent) dep. It must be emitted exactly once.
        let lock = "{\"lockfileVersion\":1,\"dependencies\":{\
            \"lodash\":{\"version\":\"4.17.21\",\"integrity\":\"sha512-a9gxpmdXtZEInkCSHUJDLHZVBgb1QS0jhss4cPP93EW7s+uC5bikET2twEF3KV+7rDblJcmNvTR7VJejqd2C2g==\"},\
            \"other\":{\"version\":\"1.0.0\",\"dependencies\":{\
                \"lodash\":{\"version\":\"4.17.21\",\"integrity\":\"sha512-a9gxpmdXtZEInkCSHUJDLHZVBgb1QS0jhss4cPP93EW7s+uC5bikET2twEF3KV+7rDblJcmNvTR7VJejqd2C2g==\"}\
            }}\
        }}";
        let (_d, ctx) = temp_ctx(&[("package-lock.json", lock)]);
        let out = NpmLockCataloger.catalog(&ctx).unwrap();
        let lodash: Vec<_> = out
            .iter()
            .filter(|c| c.name == "lodash" && c.version.as_deref() == Some("4.17.21"))
            .collect();
        assert_eq!(
            lodash.len(),
            1,
            "non-adjacent duplicate lodash must collapse to one: {}",
            out.iter().filter(|c| c.name == "lodash").count()
        );
    }

    #[test]
    fn declared_with_versioned_purl_also_sets_version() {
        // A package.json dep that matches a lockfile pin gets a versioned PURL —
        // its `version` field must agree with the PURL (not stay None).
        let pkg = "{\"name\":\"app\",\"version\":\"1.0.0\",\"dependencies\":{\"lodash\":\"^4.0\"}}";
        let lock = "{\"lockfileVersion\":3,\"packages\":{\
            \"\":{\"name\":\"app\"},\
            \"node_modules/lodash\":{\"version\":\"4.17.21\",\"integrity\":\"sha512-a9gxpmdXtZEInkCSHUJDLHZVBgb1QS0jhss4cPP93EW7s+uC5bikET2twEF3KV+7rDblJcmNvTR7VJejqd2C2g==\"}\
        }}";
        let (_d, ctx) = temp_ctx(&[("package.json", pkg), ("package-lock.json", lock)]);
        let out = NpmLockCataloger.catalog(&ctx).unwrap();
        let decl = out
            .iter()
            .find(|c| c.name == "lodash" && c.matching_method == "package_json")
            .expect("declared lodash present");
        assert_eq!(
            decl.purl.as_deref(),
            Some("pkg:npm/lodash@4.17.21"),
            "declared gets versioned PURL"
        );
        assert_eq!(
            decl.version.as_deref(),
            Some("4.17.21"),
            "version must agree with the versioned PURL, not stay None"
        );
    }

    // -----------------------------------------------------------------------
    // merge_by_identity: package.json + lock collapse
    // -----------------------------------------------------------------------

    #[test]
    fn lockfile_and_declared_merge_when_purl_matches() {
        // Build a context from a temp fixture with both package.json deps and lockfile.
        use std::io::Write;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let pkg = dir.path().join("package.json");
        let lock = dir.path().join("package-lock.json");

        let mut f = std::fs::File::create(&pkg).unwrap();
        f.write_all(
            b"{\"name\":\"app\",\"version\":\"1.0.0\",\"dependencies\":{\"lodash\":\"^4.0\"}}",
        )
        .unwrap();

        let mut f2 = std::fs::File::create(&lock).unwrap();
        f2.write_all(
            b"{\"lockfileVersion\":3,\"packages\":{\"\":{\"name\":\"app\"},\"node_modules/lodash\":{\"version\":\"4.17.21\",\"resolved\":\"https://r\",\"integrity\":\"sha512-a9gxpmdXtZEInkCSHUJDLHZVBgb1QS0jhss4cPP93EW7s+uC5bikET2twEF3KV+7rDblJcmNvTR7VJejqd2C2g==\"}}}",
        ).unwrap();

        let files = vec![pkg, lock];
        let ctx = CatalogContext::new(dir.path().to_path_buf(), files);
        let raw = NpmLockCataloger.catalog(&ctx).unwrap();
        let merged = crate::merge_by_identity(raw);

        let lodash: Vec<_> = merged
            .iter()
            .filter(|c| c.purl.as_deref() == Some("pkg:npm/lodash@4.17.21"))
            .collect();
        assert_eq!(lodash.len(), 1, "lodash must collapse to 1 component");
        assert!(lodash[0]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Declared));
        assert!(lodash[0]
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Resolved));
    }

    // -----------------------------------------------------------------------
    // exact-pin spec without a lockfile (item 7)
    // -----------------------------------------------------------------------

    #[test]
    fn is_exact_npm_version_classifies_specs() {
        // Exact pins.
        assert!(is_exact_npm_version("4.17.21"));
        assert!(is_exact_npm_version("1.0.0-beta.1"));
        assert!(is_exact_npm_version("2.0.0+build.5"));
        // Ranges / wildcards / unions / tags.
        for spec in [
            "^4.0.0",
            "~1.2.3",
            ">=1.0.0",
            "1.x",
            "1.2.X",
            "*",
            "1.0.0 || 2.0.0",
            ">=1 <2",
            "latest",
            "next",
        ] {
            assert!(!is_exact_npm_version(spec), "{spec} must not be exact");
        }
        // Non-registry specs.
        for spec in [
            "git+https://github.com/a/b.git",
            "file:../local",
            "workspace:*",
            "npm:other@1.0.0",
            "user/repo",
            "https://example.com/x.tgz",
        ] {
            assert!(!is_exact_npm_version(spec), "{spec} must not be exact");
        }
    }

    #[test]
    fn exact_pin_without_lockfile_gets_version_and_purl() {
        // No lockfile present; an exact pin must still yield a versioned component.
        let pkg = "{\"name\":\"app\",\"version\":\"1.0.0\",\"dependencies\":{\"lodash\":\"4.17.21\",\"left-pad\":\"^1.3.0\"}}";
        let (_d, ctx) = temp_ctx(&[("package.json", pkg)]);
        let out = NpmLockCataloger.catalog(&ctx).unwrap();
        let lodash = out
            .iter()
            .find(|c| c.name == "lodash" && c.matching_method == "package_json")
            .expect("lodash declared present");
        assert_eq!(lodash.version.as_deref(), Some("4.17.21"));
        assert_eq!(lodash.purl.as_deref(), Some("pkg:npm/lodash@4.17.21"));
        // A true range stays version-less (governance later adds a name-only purl).
        let left_pad = out
            .iter()
            .find(|c| c.name == "left-pad" && c.matching_method == "package_json")
            .expect("left-pad declared present");
        assert!(left_pad.version.is_none(), "a ^range is not a version");
        assert!(left_pad.purl.is_none());
    }
}
