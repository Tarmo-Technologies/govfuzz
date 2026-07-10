// SPDX-License-Identifier: Apache-2.0

//! Python ecosystem cataloger (pip / Poetry / PDM / pipenv).
//!
//! **Declared lane**: `requirements.txt` (bare `==` without `--hash`),
//! `pyproject.toml`, `Pipfile`.
//! **Resolved lane (+hash)**: `poetry.lock`, `Pipfile.lock`, `pdm.lock`, and a
//! `requirements.txt` where every entry is `==`-pinned **and** carries ≥ 1
//! `--hash=sha256:` continuation.
//!
//! # Merge strategy
//! Both lanes emit components with the same PURL (`pkg:pypi/<normalised>@<ver>`)
//! so `merge_by_identity` collapses them: the Resolved entry wins the exact
//! version and hash; the Declared entry contributes its evidence rung.
//!
//! # PURL name normalization
//! PURL: `name.to_ascii_lowercase().replace('_', "-")`.
//! Dedup identity key: PEP 503 (`[-_.]+` → `-`, lowercase) via `purl::pep503`.
//! These diverge for dotted names like `zope.interface` — PURL keeps the dot,
//! PEP 503 collapses it. We use PEP 503 as the cross-source dedup key embedded
//! in the PURL so that hand-written and lockfile entries collapse correctly.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::{Component, HashRef};
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub struct PythonCataloger;

impl Cataloger for PythonCataloger {
    fn ecosystem(&self) -> &str {
        "pypi"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files.iter().any(|p| is_requirements_file(p))
            || ctx.files_named("pyproject.toml").next().is_some()
            || ctx.files_named("Pipfile").next().is_some()
            || ctx.files_named("poetry.lock").next().is_some()
            || ctx.files_named("Pipfile.lock").next().is_some()
            || ctx.files_named("pdm.lock").next().is_some()
            || ctx.files_named("uv.lock").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();

        // Build a name → LockEntry index from lockfiles so that declared entries
        // can be assigned the resolved PURL to enable merge_by_identity collapsing.
        let mut lock_index: HashMap<String, LockEntry> = HashMap::new();

        // --- poetry.lock (Resolved) ---
        for path in ctx.files_named("poetry.lock") {
            let rel = relative_path(&ctx.root, path);
            for entry in parse_poetry_lock(path, &rel)? {
                lock_index
                    .entry(purl::pep503(&entry.name))
                    .or_insert_with(|| entry.clone());
                out.push(resolved_component(entry, "poetry_lock"));
            }
        }

        // --- Pipfile.lock (Resolved) ---
        for path in ctx.files_named("Pipfile.lock") {
            let rel = relative_path(&ctx.root, path);
            for entry in parse_pipfile_lock(path, &rel)? {
                lock_index
                    .entry(purl::pep503(&entry.name))
                    .or_insert_with(|| entry.clone());
                out.push(resolved_component(entry, "pipfile_lock"));
            }
        }

        // --- pdm.lock (Resolved) ---
        for path in ctx.files_named("pdm.lock") {
            let rel = relative_path(&ctx.root, path);
            for entry in parse_pdm_lock(path, &rel)? {
                lock_index
                    .entry(purl::pep503(&entry.name))
                    .or_insert_with(|| entry.clone());
                out.push(resolved_component(entry, "pdm_lock"));
            }
        }

        // --- uv.lock (Resolved) ---
        for path in ctx.files_named("uv.lock") {
            let rel = relative_path(&ctx.root, path);
            for entry in parse_uv_lock(path, &rel)? {
                lock_index
                    .entry(purl::pep503(&entry.name))
                    .or_insert_with(|| entry.clone());
                out.push(resolved_component(entry, "uv_lock"));
            }
        }

        // --- requirements*.txt / requirements/*.txt / constraints.txt ---
        // Each may pull in further files via `-r`/`-c` includes (recursed below,
        // behind a depth + visited-set cap). Top-level matched files are entry
        // points; included files are resolved relative to the including file.
        let mut visited: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        let req_files: Vec<PathBuf> = ctx
            .files
            .iter()
            .filter(|p| is_requirements_file(p))
            .cloned()
            .collect();
        for path in &req_files {
            let mut entries = Vec::new();
            collect_requirements(path, &ctx.root, 0, &mut visited, &mut entries);
            for entry in entries {
                let is_resolved = !entry.hashes.is_empty();
                if is_resolved {
                    lock_index
                        .entry(purl::pep503(&entry.name))
                        .or_insert_with(|| entry.clone());
                    out.push(resolved_component(entry, "requirements_txt"));
                } else {
                    out.push(declared_component(entry, &lock_index, "requirements_txt"));
                }
            }
        }

        // --- pyproject.toml (Declared) ---
        for path in ctx.files_named("pyproject.toml") {
            let rel = relative_path(&ctx.root, path);
            // The project's OWN identity (the BOM's primary subject), tagged
            // `source` so governance can adopt it as metadata.component.
            if let Some(self_component) = parse_pyproject_self_component(path, &rel)? {
                out.push(self_component);
            }
            for entry in parse_pyproject(path, &rel)? {
                out.push(declared_component(entry, &lock_index, "pyproject_toml"));
            }
        }

        // --- Pipfile (Declared) ---
        for path in ctx.files_named("Pipfile") {
            let rel = relative_path(&ctx.root, path);
            for entry in parse_pipfile(path, &rel)? {
                out.push(declared_component(entry, &lock_index, "pipfile"));
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
    name: String,
    version: String,
    hashes: Vec<HashRef>,
    relative: String,
}

fn resolved_component(entry: LockEntry, method: &str) -> Component {
    let purl_val = purl::pypi(&entry.name, &entry.version);
    let source = format!("{}:{}", entry.relative, entry.name);
    Component {
        component_ref: String::new(),
        name: entry.name,
        version: Some(entry.version),
        ecosystem: "pypi".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(purl_val),
        cpe: None,
        sha256: None,
        hashes: entry.hashes,
        identity_confidence: "high".to_owned(),
        matching_method: method.to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Resolved, source)],
        runtime_harnesses: Vec::new(),
    }
}

fn declared_component(
    entry: LockEntry,
    lock_index: &HashMap<String, LockEntry>,
    method: &str,
) -> Component {
    let source = format!("{}:{}", entry.relative, entry.name);
    // If the package is in the lockfile, use the resolved PURL so that
    // merge_by_identity can collapse this with the Resolved component.
    let purl_val = if let Some(lock) = lock_index.get(&purl::pep503(&entry.name)) {
        Some(purl::pypi(&lock.name, &lock.version))
    } else if !entry.version.is_empty() {
        // Exact pin without a lockfile entry — still emit a PURL.
        Some(purl::pypi(&entry.name, &entry.version))
    } else {
        // Range constraint or unknown → no PURL.
        None
    };
    let version = if entry.version.is_empty() {
        None
    } else {
        Some(entry.version)
    };
    Component {
        component_ref: String::new(),
        name: entry.name,
        version,
        ecosystem: "pypi".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "medium".to_owned(),
        matching_method: method.to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, source)],
        runtime_harnesses: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// requirements.txt parser
// ---------------------------------------------------------------------------

/// Maximum `-r`/`-c` include recursion depth (untrusted input — bound it).
const MAX_INCLUDE_DEPTH: usize = 10;

/// Recursively parse a requirements file plus its `-r`/`-c` includes.
/// `visited` (canonicalized paths) + a depth cap bound untrusted include chains
/// so cyclic or pathological includes terminate. Each entry is paired with the
/// relative path of the file it came from.
fn collect_requirements(
    path: &Path,
    root: &Path,
    depth: usize,
    visited: &mut std::collections::HashSet<PathBuf>,
    out: &mut Vec<LockEntry>,
) {
    if depth > MAX_INCLUDE_DEPTH {
        return;
    }
    // Use the canonical path as the visited key; fall back to the raw path.
    let canon = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(canon) {
        return;
    }
    let rel = relative_path(root, path);
    let Ok((entries, includes)) = parse_requirements(path, &rel) else {
        return;
    };
    out.extend(entries);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    for inc in includes {
        let inc_path = parent.join(&inc);
        collect_requirements(&inc_path, root, depth + 1, visited, out);
    }
}

fn parse_requirements(
    path: &Path,
    relative: &str,
) -> Result<(Vec<LockEntry>, Vec<String>), CatalogError> {
    let source = read_to_string(path)?;
    let mut out = Vec::new();
    let mut includes = Vec::new();

    // Reassemble backslash-continued logical lines.
    let logical = logical_lines(&source);

    for line in &logical {
        let line = line.trim();
        // Strip inline comments.
        let line = strip_inline_comment(line);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `-r <file>` / `-c <file>` (and `--requirement`/`--constraint`) includes.
        if let Some(inc) = parse_include_directive(line) {
            includes.push(inc);
            continue;
        }
        // Skip other directives.
        if line.starts_with('-') {
            continue;
        }

        // Direct URL reference: `name @ url` — no PyPI version.
        if line.contains(" @ ") || line.contains("@git+") || line.contains("@ git+") {
            // Extract name before `@`.
            if let Some(name) = line.split_whitespace().next() {
                let name = name.trim_end_matches('@').trim().to_owned();
                if !name.is_empty() && is_valid_package_name(&name) {
                    out.push(LockEntry {
                        name,
                        version: String::new(),
                        hashes: Vec::new(),
                        relative: relative.to_owned(),
                    });
                }
            }
            continue;
        }

        // Parse hashes (from the same logical line after backslash continuation).
        let hashes = extract_hashes(line);

        // Parse name + version spec from the PEP 508 requirement string.
        // The requirement part is everything before `;` (environment marker) and
        // before the first `--hash` option.
        let req_part = line
            .split("--hash")
            .next()
            .unwrap_or(line)
            .trim()
            .trim_end_matches('\\')
            .trim();

        let (name, version_str) = parse_pep508_name_version(req_part);
        if name.is_empty() {
            continue;
        }

        out.push(LockEntry {
            name,
            version: version_str,
            hashes,
            relative: relative.to_owned(),
        });
    }

    Ok((out, includes))
}

/// Match a `-r`/`-c`/`--requirement`/`--constraint` include directive and return
/// the referenced filename. Other `-`/`--` options (`--index-url`, `--hash`,
/// `--no-binary`, `-e`, …) are not includes.
fn parse_include_directive(line: &str) -> Option<String> {
    let mut toks = line.split_whitespace();
    let flag = toks.next()?;
    let arg = match flag {
        "-r" | "-c" | "--requirement" | "--constraint" => toks.next()?,
        _ => {
            // `--requirement=file` / `-rfile` forms.
            if let Some(rest) = flag.strip_prefix("--requirement=") {
                rest
            } else if let Some(rest) = flag.strip_prefix("--constraint=") {
                rest
            } else if let Some(rest) = flag.strip_prefix("-r").filter(|r| !r.is_empty()) {
                rest
            } else if let Some(rest) = flag.strip_prefix("-c").filter(|r| !r.is_empty()) {
                rest
            } else {
                return None;
            }
        }
    };
    let arg = arg.trim();
    if arg.is_empty() {
        None
    } else {
        Some(arg.to_owned())
    }
}

/// True if `path`'s file name is a hand-written requirements/constraints file:
/// `requirements*.txt`, any `.txt` under a `requirements/` dir, or `constraints.txt`.
fn is_requirements_file(path: &Path) -> bool {
    let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if fname == "constraints.txt" {
        return true;
    }
    if fname.starts_with("requirements") && fname.ends_with(".txt") {
        return true;
    }
    // `requirements/<anything>.txt`.
    if fname.ends_with(".txt") {
        if let Some(parent) = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
        {
            if parent == "requirements" {
                return true;
            }
        }
    }
    false
}

/// Parse `name[extras]<spec>; marker` → (name, exact_version_if_pinned).
/// Returns (name, version) where version is the exact pin if `==X.Y.Z`, or
/// empty string for ranges.
fn parse_pep508_name_version(req: &str) -> (String, String) {
    // Remove extras `[...]`.
    let no_marker = req.split(';').next().unwrap_or(req).trim();
    // Strip extras.
    let no_extras = if let Some(bracket_pos) = no_marker.find('[') {
        if let Some(close) = no_marker.find(']') {
            let before = &no_marker[..bracket_pos];
            let after = &no_marker[close + 1..];
            format!("{before}{after}")
        } else {
            no_marker.to_owned()
        }
    } else {
        no_marker.to_owned()
    };

    // Find where the name ends (first `=`, `<`, `>`, `~`, `!`, `@` after the name).
    let spec_start = no_extras
        .find(['=', '<', '>', '~', '!'])
        .unwrap_or(no_extras.len());
    let name = no_extras[..spec_start].trim().to_owned();
    let spec = no_extras[spec_start..].trim();

    if name.is_empty() || !is_valid_package_name(&name) {
        return (String::new(), String::new());
    }

    // Only emit a version for exact `==X.Y.Z` pins.
    let version = if spec.starts_with("==") && !spec.starts_with("===") {
        let v = spec[2..].trim();
        // Must not contain other specifiers (e.g. `==1.0,<2.0`).
        if v.contains(',') || v.contains('<') || v.contains('>') || v.contains('~') {
            String::new()
        } else {
            v.to_owned()
        }
    } else {
        String::new()
    };

    (name, version)
}

fn is_valid_package_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn extract_hashes(line: &str) -> Vec<HashRef> {
    let mut hashes = Vec::new();
    // Look for `--hash=sha256:<hex>` anywhere in the logical line.
    let mut remaining = line;
    while let Some(pos) = remaining.find("--hash=sha256:") {
        let after = &remaining[pos + "--hash=sha256:".len()..];
        let hex: String = after
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        if hex.len() == 64 {
            hashes.push(HashRef {
                alg: "SHA-256".to_owned(),
                value_hex: hex,
            });
        }
        remaining = &remaining[pos + 1..];
    }
    hashes
}

/// Reassemble backslash-continued lines into logical lines.
fn logical_lines(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for line in source.lines() {
        if let Some(stripped) = line.strip_suffix('\\') {
            current.push_str(stripped);
            current.push(' ');
        } else {
            current.push_str(line);
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn strip_inline_comment(s: &str) -> &str {
    // Inline comments: ` # ` — must have whitespace before `#` to avoid
    // confusing e.g. `--hash=sha256:abc#` (though sha256 are hex-only).
    if let Some(pos) = s.find(" #") {
        &s[..pos]
    } else {
        s
    }
}

// ---------------------------------------------------------------------------
// poetry.lock parser
// ---------------------------------------------------------------------------

fn parse_poetry_lock(path: &Path, relative: &str) -> Result<Vec<LockEntry>, CatalogError> {
    let source = read_to_string(path)?;
    let value: toml::Value = toml::from_str(&source).map_err(|e| CatalogError::Malformed {
        kind: "poetry.lock".to_owned(),
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;

    // Detect lock-version to pick the right files layout.
    let lock_ver = value
        .get("metadata")
        .and_then(|m| m.get("lock-version"))
        .and_then(|v| v.as_str())
        .unwrap_or("1.0");
    let is_v2 = lock_ver.starts_with('2');

    let Some(packages) = value.get("package").and_then(|v| v.as_array()) else {
        return Ok(vec![]);
    };

    // Legacy 1.x: hashes in [metadata.files].<name> array.
    let legacy_files: HashMap<String, Vec<(String, String)>> = if !is_v2 {
        let mut map = HashMap::new();
        if let Some(files_table) = value
            .get("metadata")
            .and_then(|m| m.get("files"))
            .and_then(|f| f.as_table())
        {
            for (pkg_name, file_list) in files_table {
                let mut hashes = Vec::new();
                if let Some(arr) = file_list.as_array() {
                    for item in arr {
                        if let (Some(file), Some(hash)) = (
                            item.get("file").and_then(|v| v.as_str()),
                            item.get("hash").and_then(|v| v.as_str()),
                        ) {
                            hashes.push((file.to_owned(), hash.to_owned()));
                        }
                    }
                }
                map.insert(pkg_name.clone(), hashes);
            }
        }
        map
    } else {
        HashMap::new()
    };

    let mut out = Vec::new();
    for pkg in packages {
        let Some(table) = pkg.as_table() else {
            continue;
        };
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(version) = table.get("version").and_then(|v| v.as_str()) else {
            continue;
        };

        let hashes = if is_v2 {
            // v2.x: inline [[package]].files = [{file, hash}].
            extract_poetry_inline_hashes(table)
        } else {
            // v1.x: centralized [metadata.files].<name>.
            extract_hash_refs_from_file_list(legacy_files.get(name).map(|v| v.as_slice()))
        };

        out.push(LockEntry {
            name: name.to_owned(),
            version: version.to_owned(),
            hashes,
            relative: relative.to_owned(),
        });
    }

    Ok(out)
}

fn extract_poetry_inline_hashes(table: &toml::map::Map<String, toml::Value>) -> Vec<HashRef> {
    let mut hashes = Vec::new();
    if let Some(files) = table.get("files").and_then(|v| v.as_array()) {
        for item in files {
            if let Some(hash_str) = item.get("hash").and_then(|v| v.as_str()) {
                if let Some(hex) = parse_sha256_hash_str(hash_str) {
                    hashes.push(HashRef {
                        alg: "SHA-256".to_owned(),
                        value_hex: hex,
                    });
                }
            }
        }
    }
    hashes
}

fn extract_hash_refs_from_file_list(file_list: Option<&[(String, String)]>) -> Vec<HashRef> {
    let mut hashes = Vec::new();
    if let Some(entries) = file_list {
        for (_file, hash_str) in entries {
            if let Some(hex) = parse_sha256_hash_str(hash_str) {
                hashes.push(HashRef {
                    alg: "SHA-256".to_owned(),
                    value_hex: hex,
                });
            }
        }
    }
    hashes
}

/// Parse `sha256:<64hex>` → Some(hex), or None if not a recognized sha256 hash.
fn parse_sha256_hash_str(s: &str) -> Option<String> {
    let hex = s.strip_prefix("sha256:")?;
    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hex.to_owned())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Pipfile.lock parser (JSON)
// ---------------------------------------------------------------------------

fn parse_pipfile_lock(path: &Path, relative: &str) -> Result<Vec<LockEntry>, CatalogError> {
    let source = read_to_string(path)?;
    let root: serde_json::Value =
        serde_json::from_str(&source).map_err(|e| CatalogError::Malformed {
            kind: "Pipfile.lock".to_owned(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;

    let mut out = Vec::new();
    for section in &["default", "develop"] {
        let Some(map) = root.get(*section).and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, pkg) in map {
            // Skip _meta-style keys.
            if name.starts_with('_') {
                continue;
            }
            let Some(ver_raw) = pkg.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            // Strip leading `==`.
            let version = ver_raw.trim_start_matches("==").to_owned();

            let hashes = pkg
                .get("hashes")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|h| h.as_str())
                        .filter_map(|h| {
                            let hex = h.strip_prefix("sha256:")?;
                            if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                                Some(HashRef {
                                    alg: "SHA-256".to_owned(),
                                    value_hex: hex.to_owned(),
                                })
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            out.push(LockEntry {
                name: name.clone(),
                version,
                hashes,
                relative: relative.to_owned(),
            });
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// pdm.lock parser
// ---------------------------------------------------------------------------

fn parse_pdm_lock(path: &Path, relative: &str) -> Result<Vec<LockEntry>, CatalogError> {
    let source = read_to_string(path)?;
    let value: toml::Value = toml::from_str(&source).map_err(|e| CatalogError::Malformed {
        kind: "pdm.lock".to_owned(),
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;

    let Some(packages) = value.get("package").and_then(|v| v.as_array()) else {
        return Ok(vec![]);
    };

    let mut out = Vec::new();
    for pkg in packages {
        let Some(table) = pkg.as_table() else {
            continue;
        };
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(version) = table.get("version").and_then(|v| v.as_str()) else {
            continue;
        };

        // Inline files = [{file, hash}] same as poetry v2.
        let hashes = extract_poetry_inline_hashes(table);

        out.push(LockEntry {
            name: name.to_owned(),
            version: version.to_owned(),
            hashes,
            relative: relative.to_owned(),
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// uv.lock parser (Resolved)
// ---------------------------------------------------------------------------
//
// uv.lock is TOML with `[[package]]` tables carrying `name` + `version` (always
// pinned) and the full transitive resolution. sha256 hashes live in
// `sdist = { hash = "sha256:.." }` and `wheels = [{ hash = "sha256:.." }]`.

fn parse_uv_lock(path: &Path, relative: &str) -> Result<Vec<LockEntry>, CatalogError> {
    let source = read_to_string(path)?;
    let value: toml::Value = toml::from_str(&source).map_err(|e| CatalogError::Malformed {
        kind: "uv.lock".to_owned(),
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;

    let Some(packages) = value.get("package").and_then(|v| v.as_array()) else {
        return Ok(vec![]);
    };

    let mut out = Vec::new();
    for pkg in packages {
        let Some(table) = pkg.as_table() else {
            continue;
        };
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        // A local/workspace path source has no pinned registry version we want to
        // attribute a PURL to, but uv still records a `version`. Emit it anyway —
        // governance/merge dedups against the project-self component.
        let Some(version) = table.get("version").and_then(|v| v.as_str()) else {
            continue;
        };

        let mut hashes = Vec::new();
        if let Some(hash_str) = table
            .get("sdist")
            .and_then(|s| s.get("hash"))
            .and_then(|v| v.as_str())
        {
            if let Some(hex) = parse_sha256_hash_str(hash_str) {
                hashes.push(HashRef {
                    alg: "SHA-256".to_owned(),
                    value_hex: hex,
                });
            }
        }
        if let Some(wheels) = table.get("wheels").and_then(|v| v.as_array()) {
            for wheel in wheels {
                if let Some(hash_str) = wheel.get("hash").and_then(|v| v.as_str()) {
                    if let Some(hex) = parse_sha256_hash_str(hash_str) {
                        hashes.push(HashRef {
                            alg: "SHA-256".to_owned(),
                            value_hex: hex,
                        });
                    }
                }
            }
        }

        out.push(LockEntry {
            name: name.to_owned(),
            version: version.to_owned(),
            hashes,
            relative: relative.to_owned(),
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// pyproject.toml parser (Declared)
// ---------------------------------------------------------------------------

fn parse_pyproject(path: &Path, relative: &str) -> Result<Vec<LockEntry>, CatalogError> {
    let source = read_to_string(path)?;
    let value: toml::Value = toml::from_str(&source).map_err(|e| CatalogError::Malformed {
        kind: "pyproject.toml".to_owned(),
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;

    let mut out = Vec::new();

    // PEP 621: [project].dependencies
    if let Some(deps) = value
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|v| v.as_array())
    {
        for dep in deps {
            if let Some(s) = dep.as_str() {
                let (name, version) = parse_pep508_name_version(s);
                if !name.is_empty() {
                    out.push(LockEntry {
                        name,
                        version,
                        hashes: Vec::new(),
                        relative: relative.to_owned(),
                    });
                }
            }
        }
    }

    // PEP 621: [project].optional-dependencies
    if let Some(opt_deps) = value
        .get("project")
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(|v| v.as_table())
    {
        for (_group, deps) in opt_deps {
            if let Some(arr) = deps.as_array() {
                for dep in arr {
                    if let Some(s) = dep.as_str() {
                        let (name, version) = parse_pep508_name_version(s);
                        if !name.is_empty() {
                            out.push(LockEntry {
                                name,
                                version,
                                hashes: Vec::new(),
                                relative: relative.to_owned(),
                            });
                        }
                    }
                }
            }
        }
    }

    // [tool.poetry.dependencies]
    if let Some(poetry_deps) = value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(|v| v.as_table())
    {
        for (name, dep_val) in poetry_deps {
            // Skip the `python` interpreter constraint.
            if name == "python" {
                continue;
            }
            let version = extract_poetry_dep_version(dep_val);
            out.push(LockEntry {
                name: name.clone(),
                version,
                hashes: Vec::new(),
                relative: relative.to_owned(),
            });
        }
    }

    // [tool.poetry.group.<n>.dependencies]
    if let Some(groups) = value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("group"))
        .and_then(|g| g.as_table())
    {
        for (_group_name, group_val) in groups {
            if let Some(deps) = group_val.get("dependencies").and_then(|v| v.as_table()) {
                for (name, dep_val) in deps {
                    if name == "python" {
                        continue;
                    }
                    let version = extract_poetry_dep_version(dep_val);
                    out.push(LockEntry {
                        name: name.clone(),
                        version,
                        hashes: Vec::new(),
                        relative: relative.to_owned(),
                    });
                }
            }
        }
    }

    // [tool.poetry.dev-dependencies] (legacy pre-group dev deps).
    if let Some(dev_deps) = value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dev-dependencies"))
        .and_then(|v| v.as_table())
    {
        for (name, dep_val) in dev_deps {
            if name == "python" {
                continue;
            }
            let version = extract_poetry_dep_version(dep_val);
            out.push(LockEntry {
                name: name.clone(),
                version,
                hashes: Vec::new(),
                relative: relative.to_owned(),
            });
        }
    }

    // PEP 735: [dependency-groups].<name> — array of PEP 508 strings (or
    // `{include-group = ...}` tables, which carry no package and are skipped).
    if let Some(groups) = value.get("dependency-groups").and_then(|v| v.as_table()) {
        for (_group, deps) in groups {
            let Some(arr) = deps.as_array() else { continue };
            for dep in arr {
                if let Some(s) = dep.as_str() {
                    let (name, version) = parse_pep508_name_version(s);
                    if !name.is_empty() {
                        out.push(LockEntry {
                            name,
                            version,
                            hashes: Vec::new(),
                            relative: relative.to_owned(),
                        });
                    }
                }
            }
        }
    }

    // PEP 518: [build-system].requires — the build backend(s). These are
    // CVE-bearing dependencies (e.g. setuptools) that are silently dropped if not
    // parsed; each is a PEP 508 string, scoped to the build environment.
    if let Some(reqs) = value
        .get("build-system")
        .and_then(|b| b.get("requires"))
        .and_then(|v| v.as_array())
    {
        for dep in reqs {
            if let Some(s) = dep.as_str() {
                let (name, version) = parse_pep508_name_version(s);
                if !name.is_empty() {
                    out.push(LockEntry {
                        name,
                        version,
                        hashes: Vec::new(),
                        relative: relative.to_owned(),
                    });
                }
            }
        }
    }

    // Drop a dependency that is the project itself (a `requests[socks]`-style
    // self-extra reference) — it is represented by the self-component, not a dep.
    if let Some(project_norm) = pyproject_project_name(&value).map(|n| purl::pep503(&n)) {
        out.retain(|e| purl::pep503(&e.name) != project_norm);
    }

    Ok(out)
}

/// The declared project name from `[project].name` (PEP 621) or
/// `[tool.poetry].name` (Poetry), if any.
fn pyproject_project_name(value: &toml::Value) -> Option<String> {
    value
        .get("project")
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            value
                .get("tool")
                .and_then(|t| t.get("poetry"))
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
        })
        .map(str::to_owned)
        .filter(|n| !n.is_empty())
}

/// Build the project's OWN component (the BOM's primary subject) from
/// `pyproject.toml`: name from `[project].name`/`[tool.poetry].name`, a STATIC
/// `version` (a `dynamic` version yields none), and the license expression from
/// `[project].license` (string SPDX, `{text=...}`, or `[tool.poetry].license`).
/// Tagged `component_type = "source"` / `matching_method = "pyproject_toml_project"`
/// with root-relative `Declared` evidence so governance can adopt it as
/// `metadata.component`. Returns `None` when no project name is identifiable.
fn parse_pyproject_self_component(
    path: &Path,
    relative: &str,
) -> Result<Option<Component>, CatalogError> {
    let source = read_to_string(path)?;
    let value: toml::Value = toml::from_str(&source).map_err(|e| CatalogError::Malformed {
        kind: "pyproject.toml".to_owned(),
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;

    let Some(name) = pyproject_project_name(&value) else {
        return Ok(None);
    };

    // Static version only: `[project].version` / `[tool.poetry].version`. A
    // `dynamic = ["version"]` project leaves the version unknown.
    let version = value
        .get("project")
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            value
                .get("tool")
                .and_then(|t| t.get("poetry"))
                .and_then(|p| p.get("version"))
                .and_then(|v| v.as_str())
        })
        .map(str::to_owned)
        .filter(|v| !v.is_empty());

    let license = pyproject_license(&value);

    let purl_val = match &version {
        Some(v) => Some(purl::pypi(&name, v)),
        None => purl::name_only("pypi", &name),
    };

    Ok(Some(Component {
        component_ref: String::new(),
        name,
        group: None,
        version,
        ecosystem: "pypi".to_owned(),
        component_type: "source".to_owned(),
        supplier: None,
        license,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "high".to_owned(),
        matching_method: "pyproject_toml_project".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, relative.to_owned())],
        runtime_harnesses: Vec::new(),
    }))
}

/// Extract a license expression from `[project].license` — a PEP 621 SPDX string
/// (`license = "MIT"`), a `{text = "..."}` table, or the legacy
/// `[tool.poetry].license`. A `{file = "LICENSE"}` reference carries no inline
/// SPDX id and yields `None` (the text is not resolved offline here).
fn pyproject_license(value: &toml::Value) -> Option<String> {
    if let Some(lic) = value.get("project").and_then(|p| p.get("license")) {
        match lic {
            toml::Value::String(s) if !s.trim().is_empty() => return Some(s.trim().to_owned()),
            toml::Value::Table(t) => {
                if let Some(text) = t.get("text").and_then(|v| v.as_str()) {
                    let text = text.trim();
                    // A short token is an SPDX id; a full license body is not a
                    // usable license expression, so it is left unset.
                    if !text.is_empty() && text.len() <= 64 {
                        return Some(text.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("license"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn extract_poetry_dep_version(val: &toml::Value) -> String {
    match val {
        toml::Value::String(s) => {
            // Strip Poetry's optional parens around ranges: `(>=1,<2)` → `>=1,<2`.
            let s = s.trim().trim_matches('(').trim_matches(')');
            // Only keep exact pins.
            if s.starts_with("==") && !s.contains(',') {
                s[2..].trim().to_owned()
            } else {
                String::new()
            }
        }
        toml::Value::Table(t) => t
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| {
                if s.starts_with("==") && !s.contains(',') {
                    s[2..].trim().to_owned()
                } else {
                    String::new()
                }
            })
            .unwrap_or_default(),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Pipfile parser (Declared, INI-ish TOML)
// ---------------------------------------------------------------------------

fn parse_pipfile(path: &Path, relative: &str) -> Result<Vec<LockEntry>, CatalogError> {
    let source = read_to_string(path)?;
    let value: toml::Value = toml::from_str(&source).map_err(|e| CatalogError::Malformed {
        kind: "Pipfile".to_owned(),
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;

    let mut out = Vec::new();
    for section in &["packages", "dev-packages"] {
        let Some(deps) = value.get(*section).and_then(|v| v.as_table()) else {
            continue;
        };
        for (name, dep_val) in deps {
            let version = match dep_val {
                toml::Value::String(s) => {
                    if s == "*" {
                        String::new()
                    } else if s.starts_with("==") && !s.contains(',') {
                        s[2..].trim().to_owned()
                    } else {
                        String::new()
                    }
                }
                toml::Value::Table(t) => t
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| {
                        if s.starts_with("==") && !s.contains(',') {
                            s[2..].trim().to_owned()
                        } else {
                            String::new()
                        }
                    })
                    .unwrap_or_default(),
                _ => String::new(),
            };
            out.push(LockEntry {
                name: name.clone(),
                version,
                hashes: Vec::new(),
                relative: relative.to_owned(),
            });
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
    // requirements.txt
    // -----------------------------------------------------------------------

    #[test]
    fn requirements_hash_pin_is_resolved_with_sha256() {
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        // requests has a --hash= so it's Resolved.
        let requests: Vec<_> = out
            .iter()
            .filter(|c| c.name == "requests" && c.matching_method == "requirements_txt")
            .collect();
        assert_eq!(
            requests.len(),
            1,
            "exactly one requests from requirements.txt"
        );
        let r = requests[0];
        assert_eq!(r.version.as_deref(), Some("2.32.3"));
        assert_eq!(r.purl.as_deref(), Some("pkg:pypi/requests@2.32.3"));
        assert_eq!(top_rung(&r.evidence), Some(EvidenceKind::Resolved));
        assert!(!r.hashes.is_empty(), "requests must have a hash");
        assert_eq!(r.hashes[0].alg, "SHA-256");
        assert_eq!(
            r.hashes[0].value_hex,
            "55365417734eb18255590a9ff9eb97e9e1da868d4ccd6402399eaf68af20a760"
        );
    }

    #[test]
    fn requirements_bare_pin_is_declared_without_hash() {
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        // flask has `==` but NO --hash → Declared.
        let flask: Vec<_> = out
            .iter()
            .filter(|c| c.name == "flask" && c.matching_method == "requirements_txt")
            .collect();
        assert_eq!(flask.len(), 1);
        assert_eq!(top_rung(&flask[0].evidence), Some(EvidenceKind::Declared));
        assert!(flask[0].hashes.is_empty());
    }

    #[test]
    fn requirements_direct_url_has_no_version() {
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let direct: Vec<_> = out.iter().filter(|c| c.name == "mypackage").collect();
        assert_eq!(direct.len(), 1);
        assert!(direct[0].version.is_none());
        assert!(direct[0].purl.is_none());
    }

    #[test]
    fn requirements_typing_extensions_has_pypi_purl() {
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let te: Vec<_> = out
            .iter()
            .filter(|c| c.name == "typing_extensions" && c.matching_method == "requirements_txt")
            .collect();
        assert_eq!(te.len(), 1);
        // PURL: underscore → dash, lowercase.
        assert_eq!(
            te[0].purl.as_deref(),
            Some("pkg:pypi/typing-extensions@4.12.2")
        );
    }

    // -----------------------------------------------------------------------
    // -r / -c includes, requirements*.txt globs, constraints.txt
    // -----------------------------------------------------------------------

    #[test]
    fn requirements_r_include_pulls_base_pins() {
        // requirements.txt has `-r base.txt`; base.txt pins click==8.1.7.
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let click: Vec<_> = out.iter().filter(|c| c.name == "click").collect();
        assert_eq!(click.len(), 1, "click pulled from -r base.txt include");
        assert_eq!(click[0].version.as_deref(), Some("8.1.7"));
    }

    #[test]
    fn requirements_dev_glob_is_picked_up() {
        // requirements-dev.txt is matched by the requirements*.txt glob.
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let cov: Vec<_> = out.iter().filter(|c| c.name == "pytest-cov").collect();
        assert_eq!(cov.len(), 1, "pytest-cov from requirements-dev.txt");
        assert_eq!(cov[0].version.as_deref(), Some("5.0.0"));
    }

    #[test]
    fn constraints_txt_is_picked_up() {
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let pkg: Vec<_> = out.iter().filter(|c| c.name == "packaging").collect();
        assert_eq!(pkg.len(), 1, "packaging from constraints.txt");
        assert_eq!(pkg[0].version.as_deref(), Some("24.0"));
    }

    #[test]
    fn cyclic_include_terminates() {
        // A pair of mutually-including requirements files must not hang or panic.
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let a = dir.path().join("requirements.txt");
        let b = dir.path().join("more.txt");
        std::fs::File::create(&a)
            .unwrap()
            .write_all(b"-r more.txt\nalpha==1.0.0\n")
            .unwrap();
        std::fs::File::create(&b)
            .unwrap()
            .write_all(b"-r requirements.txt\nbeta==2.0.0\n")
            .unwrap();
        let ctx = CatalogContext::new(dir.path().to_path_buf(), vec![a, b]);
        let out = PythonCataloger.catalog(&ctx).unwrap();
        // Both pins are reachable; neither appears more than once (visited-set).
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names.iter().filter(|n| **n == "alpha").count(), 1);
        assert_eq!(names.iter().filter(|n| **n == "beta").count(), 1);
    }

    #[test]
    fn deep_include_chain_is_bounded() {
        // A long chain of -r includes must terminate under the depth cap without
        // panicking. (We do not assert on the deepest pins past the cap.)
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let mut files = Vec::new();
        for i in 0..30 {
            let p = if i == 0 {
                dir.path().join("requirements.txt")
            } else {
                dir.path().join(format!("r{i}.txt"))
            };
            let body = format!("-r r{}.txt\npkg{i}==1.0.{i}\n", i + 1);
            std::fs::File::create(&p)
                .unwrap()
                .write_all(body.as_bytes())
                .unwrap();
            files.push(p);
        }
        let ctx = CatalogContext::new(dir.path().to_path_buf(), files);
        // Must not panic/hang.
        let out = PythonCataloger.catalog(&ctx).unwrap();
        assert!(out.iter().any(|c| c.name == "pkg0"));
    }

    // -----------------------------------------------------------------------
    // pyproject: poetry dev-dependencies + PEP 735 dependency-groups
    // -----------------------------------------------------------------------

    #[test]
    fn poetry_legacy_dev_dependencies_are_read() {
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let black: Vec<_> = out
            .iter()
            .filter(|c| c.name == "black" && c.matching_method == "pyproject_toml")
            .collect();
        assert_eq!(black.len(), 1, "[tool.poetry.dev-dependencies] black read");
        assert_eq!(black[0].version.as_deref(), Some("24.4.2"));
    }

    #[test]
    fn pep735_dependency_groups_are_read() {
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let cov: Vec<_> = out
            .iter()
            .filter(|c| c.name == "coverage" && c.matching_method == "pyproject_toml")
            .collect();
        assert_eq!(cov.len(), 1, "[dependency-groups] coverage read");
        assert_eq!(cov[0].version.as_deref(), Some("7.5.0"));
    }

    #[test]
    fn detect_true_for_requirements_glob_and_constraints() {
        let dev = CatalogContext::new("/r".into(), vec!["/r/requirements-dev.txt".into()]);
        assert!(PythonCataloger.detect(&dev));
        let con = CatalogContext::new("/r".into(), vec!["/r/constraints.txt".into()]);
        assert!(PythonCataloger.detect(&con));
        let nested = CatalogContext::new("/r".into(), vec!["/r/requirements/base.txt".into()]);
        assert!(PythonCataloger.detect(&nested));
    }

    // -----------------------------------------------------------------------
    // poetry.lock
    // -----------------------------------------------------------------------

    #[test]
    fn poetry_lock_yields_resolved_with_inline_hashes() {
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let poetry_requests: Vec<_> = out
            .iter()
            .filter(|c| c.name == "requests" && c.matching_method == "poetry_lock")
            .collect();
        assert_eq!(poetry_requests.len(), 1);
        let r = poetry_requests[0];
        assert_eq!(r.version.as_deref(), Some("2.32.3"));
        assert_eq!(r.purl.as_deref(), Some("pkg:pypi/requests@2.32.3"));
        assert_eq!(top_rung(&r.evidence), Some(EvidenceKind::Resolved));
        assert!(!r.hashes.is_empty());
        // One of the hashes should match the fixture tarball hash.
        let has_tarball_hash = r.hashes.iter().any(|h| {
            h.value_hex == "55365417734eb18255590a9ff9eb97e9e1da868d4ccd6402399eaf68af20a760"
        });
        assert!(has_tarball_hash, "poetry tarball SHA-256 must be present");
    }

    #[test]
    fn poetry_lock_does_not_emit_content_hash_as_component() {
        // The [metadata].content-hash is a staleness fingerprint, not a component.
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        // No component should have a name that looks like a SHA-256 hex string.
        for c in &out {
            assert!(
                c.name.len() < 64 || !c.name.chars().all(|ch| ch.is_ascii_hexdigit()),
                "content-hash leaked as a component name: {}",
                c.name
            );
        }
        // Also assert no component has the known content-hash as its version.
        let staleness = "d9aef3b2b3c88b28fefb4b5f2d4a5e6c8f0a1b3c4d5e6f7a8b9c0d1e2f3a4b5";
        for c in &out {
            assert_ne!(
                c.version.as_deref(),
                Some(staleness),
                "content-hash must not be emitted as a version"
            );
        }
    }

    // -----------------------------------------------------------------------
    // uv.lock
    // -----------------------------------------------------------------------

    #[test]
    fn uv_lock_yields_resolved_pinned_versions_with_hashes() {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let lock = dir.path().join("uv.lock");
        let mut f = std::fs::File::create(&lock).unwrap();
        f.write_all(
            br#"version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "click"
version = "8.1.7"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://x/click-8.1.7.tar.gz", hash = "sha256:ca9853ad459e787e2192211578cc907e7594e294c7ccc834310722b41b9ca6de", size = 336121 }
wheels = [
    { url = "https://x/click-8.1.7-py3-none-any.whl", hash = "sha256:ae74fb96c20a0277a1d615f1e4d73c8414f5a98db8b799a7931d1582f3390c28", size = 97941 },
]

[[package]]
name = "colorama"
version = "0.4.6"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://x/colorama-0.4.6-py2.py3-none-any.whl", hash = "sha256:4f1d9991f5acc0ca119f9d443620b77f9d6b33703e51011c16baf57afb285fc6", size = 25335 },
]
"#,
        )
        .unwrap();
        let ctx = CatalogContext::new(dir.path().into(), vec![lock]);
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let click: Vec<_> = out
            .iter()
            .filter(|c| c.name == "click" && c.matching_method == "uv_lock")
            .collect();
        assert_eq!(click.len(), 1, "exactly one resolved click from uv.lock");
        let c = click[0];
        assert_eq!(c.version.as_deref(), Some("8.1.7"));
        assert_eq!(c.purl.as_deref(), Some("pkg:pypi/click@8.1.7"));
        assert_eq!(top_rung(&c.evidence), Some(EvidenceKind::Resolved));
        assert!(
            c.hashes.iter().any(|h| h.value_hex.starts_with("ca9853ad")),
            "sdist hash present"
        );
        // Transitive dep with wheel-only hash is also pinned.
        let colorama: Vec<_> = out.iter().filter(|c| c.name == "colorama").collect();
        assert_eq!(colorama.len(), 1);
        assert_eq!(colorama[0].version.as_deref(), Some("0.4.6"));
    }

    #[test]
    fn uv_lock_detects() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/uv.lock".into()]);
        assert!(PythonCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // Pipfile.lock
    // -----------------------------------------------------------------------

    #[test]
    fn pipfile_lock_strips_leading_eq_eq_from_version() {
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let certifi: Vec<_> = out
            .iter()
            .filter(|c| c.name == "certifi" && c.matching_method == "pipfile_lock")
            .collect();
        assert_eq!(certifi.len(), 1);
        // Pipfile.lock version is `==2024.2.2` → strip `==`.
        assert_eq!(certifi[0].version.as_deref(), Some("2024.2.2"));
        assert_eq!(
            certifi[0].purl.as_deref(),
            Some("pkg:pypi/certifi@2024.2.2")
        );
        assert_eq!(top_rung(&certifi[0].evidence), Some(EvidenceKind::Resolved));
    }

    #[test]
    fn pipfile_lock_does_not_emit_meta_hash_as_component() {
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        // _meta key should be skipped; no component named "_meta".
        assert!(out.iter().all(|c| c.name != "_meta"));
    }

    #[test]
    fn pipfile_lock_multi_hash_package() {
        let ctx = fixture_ctx("python");
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let urllib3: Vec<_> = out
            .iter()
            .filter(|c| c.name == "urllib3" && c.matching_method == "pipfile_lock")
            .collect();
        assert_eq!(urllib3.len(), 1);
        assert_eq!(
            urllib3[0].hashes.len(),
            2,
            "urllib3 has 2 hashes in fixture"
        );
    }

    // -----------------------------------------------------------------------
    // Detect
    // -----------------------------------------------------------------------

    #[test]
    fn detect_true_for_requirements_txt() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/requirements.txt".into()]);
        assert!(PythonCataloger.detect(&ctx));
    }

    #[test]
    fn detect_false_without_python_files() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/Cargo.toml".into()]);
        assert!(!PythonCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // merge_by_identity: manifest + lockfile collapse into one component
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_and_lockfile_merge_for_requests() {
        let ctx = fixture_ctx("python");
        // Emit all, then merge.
        let raw = PythonCataloger.catalog(&ctx).unwrap();
        let merged = crate::merge_by_identity(raw);
        // requests appears in both requirements.txt (Resolved) and poetry.lock (Resolved)
        // — both share the same PURL so they collapse to 1.
        let reqs: Vec<_> = merged
            .iter()
            .filter(|c| {
                c.purl.as_deref() == Some("pkg:pypi/requests@2.32.3") && c.ecosystem == "pypi"
            })
            .collect();
        assert_eq!(
            reqs.len(),
            1,
            "requests must collapse to 1 component after merge"
        );
    }

    // -----------------------------------------------------------------------
    // pep503 dedup key
    // -----------------------------------------------------------------------

    #[test]
    fn pep503_key_differs_from_purl_name_for_dotted() {
        // typing_extensions: PURL = pkg:pypi/typing-extensions, PEP503 = typing-extensions
        // (same in this case). But zope.interface would differ: PURL keeps dot.
        assert_eq!(purl::pep503("typing_extensions"), "typing-extensions");
        assert_eq!(
            purl::pypi("typing_extensions", "4.0"),
            "pkg:pypi/typing-extensions@4.0"
        );
        // dotted name: PURL keeps dot, PEP503 collapses it.
        assert_eq!(
            purl::pypi("zope.interface", "6.0"),
            "pkg:pypi/zope.interface@6.0"
        );
        assert_eq!(purl::pep503("zope.interface"), "zope-interface");
    }

    // -----------------------------------------------------------------------
    // PEP 518 build-system.requires + project self-component
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
    fn build_system_requires_are_catalogued() {
        // PEP 518 [build-system].requires backends (setuptools) must be emitted —
        // they are CVE-bearing and were previously dropped.
        let (_d, ctx) = temp_ctx(&[(
            "pyproject.toml",
            "[build-system]\nrequires = [\"setuptools>=61\", \"wheel\"]\nbuild-backend = \"setuptools.build_meta\"\n[project]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )]);
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let names: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "pyproject_toml")
            .map(|c| c.name.as_str())
            .collect();
        assert!(
            names.contains(&"setuptools"),
            "build backend setuptools dropped: {names:?}"
        );
        assert!(names.contains(&"wheel"), "wheel dropped: {names:?}");
    }

    #[test]
    fn pyproject_self_component_is_emitted_with_license_and_version() {
        let (_d, ctx) = temp_ctx(&[(
            "pyproject.toml",
            "[project]\nname = \"My_Pkg\"\nversion = \"1.2.3\"\nlicense = \"MIT\"\n",
        )]);
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let self_comp = out
            .iter()
            .find(|c| c.matching_method == "pyproject_toml_project")
            .expect("a project self-component must be emitted");
        assert_eq!(self_comp.component_type, "source");
        assert_eq!(self_comp.version.as_deref(), Some("1.2.3"));
        assert_eq!(self_comp.license.as_deref(), Some("MIT"));
        // PURL name is PEP-normalized (lowercase, `_`→`-`).
        assert_eq!(self_comp.purl.as_deref(), Some("pkg:pypi/my-pkg@1.2.3"));
        assert_eq!(self_comp.evidence_summary(), "pyproject.toml");
    }

    #[test]
    fn pyproject_self_component_license_table_text() {
        let (_d, ctx) = temp_ctx(&[(
            "pyproject.toml",
            "[project]\nname = \"demo\"\nversion = \"1.0\"\nlicense = {text = \"Apache-2.0\"}\n",
        )]);
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let self_comp = out
            .iter()
            .find(|c| c.matching_method == "pyproject_toml_project")
            .unwrap();
        assert_eq!(self_comp.license.as_deref(), Some("Apache-2.0"));
    }

    #[test]
    fn self_referential_extra_dependency_is_skipped() {
        // A `name[extra]` dependency referencing the project itself (the
        // `requests[socks]` pattern) must not appear as a dependency component.
        let (_d, ctx) = temp_ctx(&[(
            "pyproject.toml",
            "[project]\nname = \"requests\"\nversion = \"2.0\"\n\
             dependencies = [\"requests[socks]==2.0\", \"click==8.0\"]\n",
        )]);
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let deps: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "pyproject_toml")
            .map(|c| c.name.as_str())
            .collect();
        assert!(deps.contains(&"click"), "click must remain: {deps:?}");
        assert!(
            !deps.contains(&"requests"),
            "the self-extra dependency must be skipped: {deps:?}"
        );
    }

    #[test]
    fn dynamic_version_self_component_has_no_version() {
        let (_d, ctx) = temp_ctx(&[(
            "pyproject.toml",
            "[project]\nname = \"demo\"\ndynamic = [\"version\"]\n",
        )]);
        let out = PythonCataloger.catalog(&ctx).unwrap();
        let self_comp = out
            .iter()
            .find(|c| c.matching_method == "pyproject_toml_project")
            .unwrap();
        assert!(self_comp.version.is_none());
        assert_eq!(self_comp.purl.as_deref(), Some("pkg:pypi/demo"));
    }
}
