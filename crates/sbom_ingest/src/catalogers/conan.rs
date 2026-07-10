// SPDX-License-Identifier: Apache-2.0

//! Conan (C/C++) ecosystem cataloger.
//!
//! **Declared**: `conanfile.txt` (INI `[requires]`/`[tool_requires]`/
//! `[test_requires]`/`[build_requires]` sections) and `conanfile.py`
//! (static regex extraction — **never executed**).
//!
//! **Resolved** (+rrev qualifier): `conan.lock` (Conan 2.x JSON flat arrays).
//! Conan 1.x nested `graph_lock`/`nodes` shape is detected and skipped gracefully.
//!
//! # PURL
//! `pkg:conan/<name>@<version>` for ConanCenter packages (no user/channel).
//! When user/channel are present they would be `?user=&channel=` qualifiers; this
//! cataloger records them in the PURL when non-empty.  The `#rrev` (recipe hash)
//! becomes `?rrev=<hex>`; `%timestamp` is **stripped** before PURL construction.
//!
//! # Conan 1.x vs 2.x detection
//! 2.x: top-level JSON object with a `"requires"` or `"build_requires"` key whose
//! value is an array of strings.  1.x: top-level `"graph_lock"` / `"nodes"` dict.
//!
//! # Untrusted input
//! All files are size-bounded (≤4 MiB).  `conanfile.py` is never executed.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::Component;
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct ConanCataloger;

impl Cataloger for ConanCataloger {
    fn ecosystem(&self) -> &str {
        "conan"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("conanfile.txt").next().is_some()
            || ctx.files_named("conanfile.py").next().is_some()
            || ctx.files_named("conan.lock").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();

        // Build a lock index from conan.lock (Resolved).
        let mut lock_index: HashMap<String, LockEntry> = HashMap::new();
        for lock_path in ctx.files_named("conan.lock") {
            let rel = relative_path(&ctx.root, lock_path);
            for entry in parse_conan_lock(lock_path, &rel)? {
                let key = entry.name.to_ascii_lowercase();
                lock_index.entry(key).or_insert_with(|| entry.clone());
                out.push(lock_entry_to_component(&entry));
            }
        }

        // conanfile.txt → Declared.
        for path in ctx.files_named("conanfile.txt") {
            let rel = relative_path(&ctx.root, path);
            for dep in parse_conanfile_txt(path, &rel)? {
                out.push(declared_component(dep, &lock_index));
            }
        }

        // conanfile.py → Declared (static extraction, no exec).
        for path in ctx.files_named("conanfile.py") {
            let rel = relative_path(&ctx.root, path);
            for dep in parse_conanfile_py(path, &rel)? {
                out.push(declared_component(dep, &lock_index));
            }
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Internal data
// ---------------------------------------------------------------------------

/// A fully-parsed Conan package reference.
#[derive(Debug, Clone)]
struct ConanRef {
    name: String,
    version: Option<String>, // None for ranges like [>=1.0]
    user: Option<String>,
    channel: Option<String>,
    rrev: Option<String>,
    relative: String,
    section: String, // e.g. "requires", "tool_requires"
}

/// An entry from conan.lock (Resolved).
#[derive(Debug, Clone)]
struct LockEntry {
    name: String,
    version: String,
    user: Option<String>,
    channel: Option<String>,
    rrev: Option<String>,
    relative: String,
}

// ---------------------------------------------------------------------------
// conan.lock parser (Conan 2.x)
// ---------------------------------------------------------------------------

fn parse_conan_lock(path: &Path, relative: &str) -> Result<Vec<LockEntry>, CatalogError> {
    let source = read_bounded(path)?;
    let root: serde_json::Value =
        serde_json::from_str(&source).map_err(|e| CatalogError::Malformed {
            kind: "conan.lock".to_owned(),
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;

    // Detect Conan 1.x by the presence of a "graph_lock" key → skip.
    if root.get("graph_lock").is_some() || root.get("nodes").is_some() {
        // Conan 1.x lockfile — structure differs significantly; skip for now.
        return Ok(vec![]);
    }

    // Conan 2.x: flat string arrays in requires/build_requires/etc.
    let mut entries = Vec::new();
    for key in &[
        "requires",
        "build_requires",
        "python_requires",
        "config_requires",
    ] {
        if let Some(arr) = root.get(key).and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(ref_str) = item.as_str() {
                    if let Some(entry) = parse_lock_ref(ref_str, relative) {
                        entries.push(entry);
                    }
                }
            }
        }
    }

    Ok(entries)
}

/// Parse a single Conan 2.x lock reference string:
/// `name/version[@user/channel][#rrev][%timestamp]`
fn parse_lock_ref(s: &str, relative: &str) -> Option<LockEntry> {
    // Strip %timestamp suffix first.
    let s = s.split('%').next().unwrap_or(s);

    // Split on # to get rrev.
    let (base, rrev) = if let Some(idx) = s.find('#') {
        (&s[..idx], Some(s[idx + 1..].to_owned()))
    } else {
        (s, None)
    };

    // base is `name/version[@user/channel]` or `name/version@user/channel`.
    // Split on first `/` → name, rest.
    let slash_idx = base.find('/')?;
    let name = base[..slash_idx].trim().to_owned();
    if name.is_empty() {
        return None;
    }
    let rest = &base[slash_idx + 1..];

    // rest is `version[@user/channel]` or `version@user/channel`.
    let (version_part, user_channel) = if let Some(at_idx) = rest.find('@') {
        (&rest[..at_idx], Some(&rest[at_idx + 1..]))
    } else {
        (rest, None)
    };

    let version = version_part.trim().to_owned();
    if version.is_empty() {
        return None;
    }

    let (user, channel) = if let Some(uc) = user_channel {
        let mut parts = uc.splitn(2, '/');
        let u = parts.next().map(|s| s.to_owned()).filter(|s| !s.is_empty());
        let c = parts.next().map(|s| s.to_owned()).filter(|s| !s.is_empty());
        (u, c)
    } else {
        (None, None)
    };

    Some(LockEntry {
        name,
        version,
        user,
        channel,
        rrev,
        relative: relative.to_owned(),
    })
}

fn lock_entry_to_component(entry: &LockEntry) -> Component {
    let purl_val = build_conan_purl(
        &entry.name,
        &entry.version,
        entry.user.as_deref(),
        entry.channel.as_deref(),
        entry.rrev.as_deref(),
    );
    let source = format!("{}:{}", entry.relative, entry.name);
    Component {
        component_ref: String::new(),
        name: entry.name.clone(),
        version: Some(entry.version.clone()),
        ecosystem: "conan".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(purl_val),
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "high".to_owned(),
        matching_method: "conan_lock".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Resolved, source)],
        runtime_harnesses: Vec::new(),
    }
}

/// Build a `pkg:conan/...` PURL string, adding user/channel/rrev qualifiers.
fn build_conan_purl(
    name: &str,
    version: &str,
    user: Option<&str>,
    channel: Option<&str>,
    rrev: Option<&str>,
) -> String {
    let base = purl::conan(name, version);
    let mut qualifiers: Vec<String> = Vec::new();
    if let Some(u) = user {
        qualifiers.push(format!("user={u}"));
    }
    if let Some(c) = channel {
        qualifiers.push(format!("channel={c}"));
    }
    if let Some(r) = rrev {
        qualifiers.push(format!("rrev={r}"));
    }
    if qualifiers.is_empty() {
        base
    } else {
        format!("{}?{}", base, qualifiers.join("&"))
    }
}

// ---------------------------------------------------------------------------
// conanfile.txt parser
// ---------------------------------------------------------------------------

fn parse_conanfile_txt(path: &Path, relative: &str) -> Result<Vec<ConanRef>, CatalogError> {
    let source = read_bounded(path)?;
    let mut out = Vec::new();
    let mut current_section: Option<String> = None;

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Section header?
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = Some(trimmed[1..trimmed.len() - 1].to_ascii_lowercase());
            continue;
        }
        // Only process dependency sections.
        let section = match current_section.as_deref() {
            Some(s @ ("requires" | "tool_requires" | "test_requires" | "build_requires")) => {
                s.to_owned()
            }
            _ => continue,
        };

        if let Some(cr) = parse_conan_ref_str(trimmed, relative, &section) {
            out.push(cr);
        }
    }

    Ok(out)
}

/// Parse one Conan reference line: `name/version[@user/channel][#rrev]`
/// or a version range `[>=1.0 <2.0]` (⇒ no pinned version).
fn parse_conan_ref_str(s: &str, relative: &str, section: &str) -> Option<ConanRef> {
    // Version range — starts with `[` but isn't a section header.
    if s.starts_with('[') {
        // Extract the name by looking for it before the `[` (sometimes `name[>=1.0]`).
        let bracket = s.find('[').unwrap_or(0);
        let name_part = s[..bracket].trim();
        let name = if name_part.is_empty() {
            return None; // bare range, no name
        } else {
            name_part.to_owned()
        };
        return Some(ConanRef {
            name,
            version: None, // range → no pin
            user: None,
            channel: None,
            rrev: None,
            relative: relative.to_owned(),
            section: section.to_owned(),
        });
    }

    // Strip rrev (#...) from input before further parsing.
    let (base, rrev) = if let Some(idx) = s.find('#') {
        (&s[..idx], Some(s[idx + 1..].to_owned()))
    } else {
        (s, None)
    };

    let slash_idx = base.find('/')?;
    let name = base[..slash_idx].trim().to_owned();
    if name.is_empty() {
        return None;
    }
    let rest = &base[slash_idx + 1..];

    let (version_part, user_channel) = if let Some(at_idx) = rest.find('@') {
        (&rest[..at_idx], Some(&rest[at_idx + 1..]))
    } else {
        (rest, None)
    };

    let version_str = version_part.trim();
    // If version looks like a range (contains spaces or comparison operators), treat as None.
    let version = if version_str.is_empty()
        || version_str.contains(' ')
        || version_str.contains('>')
        || version_str.contains('<')
        || version_str.contains('=')
    {
        None
    } else {
        Some(version_str.to_owned())
    };

    let (user, channel) = if let Some(uc) = user_channel {
        let mut parts = uc.splitn(2, '/');
        let u = parts.next().map(|s| s.to_owned()).filter(|s| !s.is_empty());
        let c = parts.next().map(|s| s.to_owned()).filter(|s| !s.is_empty());
        (u, c)
    } else {
        (None, None)
    };

    Some(ConanRef {
        name,
        version,
        user,
        channel,
        rrev,
        relative: relative.to_owned(),
        section: section.to_owned(),
    })
}

fn declared_component(dep: ConanRef, lock_index: &HashMap<String, LockEntry>) -> Component {
    let key = dep.name.to_ascii_lowercase();
    let source = format!("{}:{}", dep.relative, dep.name);

    // Try to resolve from lock index.
    if let Some(entry) = lock_index.get(&key) {
        let purl_val = build_conan_purl(
            &entry.name,
            &entry.version,
            entry.user.as_deref(),
            entry.channel.as_deref(),
            entry.rrev.as_deref(),
        );
        return Component {
            component_ref: String::new(),
            name: dep.name.clone(),
            version: Some(entry.version.clone()),
            ecosystem: "conan".to_owned(),
            group: None,
            component_type: "library".to_owned(),
            supplier: None,
            license: None,
            purl: Some(purl_val),
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "medium".to_owned(),
            matching_method: format!("conanfile_{}", dep.section),
            evidence: vec![Evidence::new(EvidenceKind::Declared, source)],
            runtime_harnesses: Vec::new(),
        };
    }

    // Declared-only.
    let (version, purl_val) = if let Some(ref v) = dep.version {
        let purl = build_conan_purl(
            &dep.name,
            v,
            dep.user.as_deref(),
            dep.channel.as_deref(),
            dep.rrev.as_deref(),
        );
        (Some(v.clone()), Some(purl))
    } else {
        (None, None)
    };

    Component {
        component_ref: String::new(),
        name: dep.name.clone(),
        version,
        ecosystem: "conan".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "low".to_owned(),
        matching_method: format!("conanfile_{}", dep.section),
        evidence: vec![Evidence::new(EvidenceKind::Declared, source)],
        runtime_harnesses: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// conanfile.py — static extraction (NEVER executed)
// ---------------------------------------------------------------------------

/// Regex-free static extraction from conanfile.py.
/// Extracts string literals from class-level `requires`/`tool_requires` attrs
/// and `self.requires(...)` / `self.tool_requires(...)` calls.
fn parse_conanfile_py(path: &Path, relative: &str) -> Result<Vec<ConanRef>, CatalogError> {
    let source = read_bounded(path)?;
    let mut out = Vec::new();

    // When a `requires = ( ... )` / `[ ... ]` assignment spans multiple lines,
    // `continuation` holds the active section and the running bracket depth so
    // subsequent lines keep contributing string literals until brackets balance.
    let mut continuation: Option<(&'static str, i32)> = None;

    for line in source.lines() {
        let trimmed = line.trim();

        // Skip comments.
        if trimmed.starts_with('#') {
            continue;
        }

        // Inside an open multi-line tuple/list: keep collecting literals and track
        // bracket depth until it returns to zero.
        if let Some((section, depth)) = continuation {
            for s in extract_string_literals(trimmed) {
                if s.contains('/') {
                    if let Some(cr) = parse_conan_ref_str(&s, relative, section) {
                        out.push(cr);
                    }
                }
            }
            let new_depth = depth + bracket_delta(trimmed);
            if new_depth <= 0 {
                continuation = None;
            } else {
                continuation = Some((section, new_depth));
            }
            continue;
        }

        // Class-level attributes: `requires = "zlib/1.3.1"` or tuple/list.
        // Call-form: `self.requires("zlib/1.3.1")`.
        let section = if trimmed.starts_with("python_requires") {
            "python_requires"
        } else if trimmed.starts_with("tool_requires") || trimmed.contains("self.tool_requires(") {
            "tool_requires"
        } else if trimmed.starts_with("build_requires") || trimmed.contains("self.build_requires(")
        {
            "build_requires"
        } else if trimmed.starts_with("test_requires") || trimmed.contains("self.test_requires(") {
            "test_requires"
        } else if (trimmed.starts_with("requires")
            && !trimmed.starts_with("requirements")
            && !trimmed.starts_with("requires_conan"))
            || trimmed.contains("self.requires(")
        {
            "requires"
        } else {
            continue;
        };

        // Extract all string literals on this (first) line.
        for s in extract_string_literals(trimmed) {
            if s.contains('/') {
                if let Some(cr) = parse_conan_ref_str(&s, relative, section) {
                    out.push(cr);
                }
            }
        }

        // If the assignment opens a tuple/list that is not closed on this line,
        // continue collecting on subsequent lines.
        let depth = bracket_delta(trimmed);
        if depth > 0 {
            continuation = Some((section, depth));
        }
    }

    Ok(out)
}

/// Net bracket depth change for a line, counting `(`/`[` as +1 and `)`/`]` as -1,
/// **ignoring brackets inside string literals**. Used to track multi-line
/// `requires`/`tool_requires`/… tuple or list assignments.
fn bracket_delta(line: &str) -> i32 {
    let mut depth = 0i32;
    let mut in_str: Option<char> = None;
    let mut escaped = false;
    for ch in line.chars() {
        if let Some(q) = in_str {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                in_str = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => in_str = Some(ch),
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            '#' => break, // trailing comment — stop counting
            _ => {}
        }
    }
    depth
}

/// Extract string literals delimited by `"` or `'` from a line.
fn extract_string_literals(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '"' || chars[i] == '\'' {
            let quote = chars[i];
            i += 1;
            let start = i;
            while i < chars.len() && chars[i] != quote {
                // Handle simple escaped quotes.
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            if !s.is_empty() {
                out.push(s);
            }
        }
        i += 1;
    }
    out
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
        return Ok(String::new()); // too large — treat as empty
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
    // conan.lock (Resolved) parsing
    // -----------------------------------------------------------------------

    #[test]
    fn conan_lock_yields_resolved_components() {
        let ctx = fixture_ctx("conan");
        let out = ConanCataloger.catalog(&ctx).unwrap();
        let resolved: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "conan_lock")
            .collect();
        assert!(
            !resolved.is_empty(),
            "conan.lock must yield resolved components"
        );
        let names: Vec<_> = resolved.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"zlib"), "zlib must be present");
        assert!(names.contains(&"openssl"), "openssl must be present");
    }

    #[test]
    fn conan_lock_timestamp_stripped_from_purl() {
        let ctx = fixture_ctx("conan");
        let out = ConanCataloger.catalog(&ctx).unwrap();
        // PURLs must not contain a % (timestamp separator).
        for c in out.iter().filter(|c| c.matching_method == "conan_lock") {
            let purl = c.purl.as_deref().unwrap_or("");
            assert!(
                !purl.contains('%'),
                "PURL must not contain timestamp: {purl}"
            );
        }
    }

    #[test]
    fn conan_lock_rrev_in_purl_qualifier() {
        let ctx = fixture_ctx("conan");
        let out = ConanCataloger.catalog(&ctx).unwrap();
        let zlib = out
            .iter()
            .find(|c| c.matching_method == "conan_lock" && c.name == "zlib")
            .expect("zlib from lock must be present");
        let purl = zlib.purl.as_deref().unwrap_or("");
        // rrev present → ?rrev= qualifier.
        assert!(
            purl.contains("rrev="),
            "zlib lock entry must have rrev qualifier: {purl}"
        );
        assert_eq!(
            purl,
            "pkg:conan/zlib@1.3.1?rrev=06023034579559bb64357db3a53f88a4"
        );
    }

    #[test]
    fn conan_lock_with_user_channel() {
        let ctx = fixture_ctx("conan");
        let out = ConanCataloger.catalog(&ctx).unwrap();
        let openssl = out
            .iter()
            .find(|c| c.matching_method == "conan_lock" && c.name == "openssl")
            .expect("openssl must be present");
        let purl = openssl.purl.as_deref().unwrap_or("");
        assert!(
            purl.contains("user=bincrafters"),
            "must have user qualifier: {purl}"
        );
        assert!(
            purl.contains("channel=stable"),
            "must have channel qualifier: {purl}"
        );
    }

    #[test]
    fn conan_lock_evidence_is_resolved() {
        let ctx = fixture_ctx("conan");
        let out = ConanCataloger.catalog(&ctx).unwrap();
        for c in out.iter().filter(|c| c.matching_method == "conan_lock") {
            assert_eq!(
                top_rung(&c.evidence),
                Some(EvidenceKind::Resolved),
                "{} must be Resolved",
                c.name
            );
        }
    }

    // -----------------------------------------------------------------------
    // conanfile.txt (Declared) parsing
    // -----------------------------------------------------------------------

    #[test]
    fn conanfile_txt_yields_declared_components() {
        let ctx = fixture_ctx("conan");
        let out = ConanCataloger.catalog(&ctx).unwrap();
        let declared: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method.starts_with("conanfile_"))
            .collect();
        assert!(
            !declared.is_empty(),
            "conanfile.txt must yield declared components"
        );
        let names: Vec<_> = declared.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"boost"), "boost must be declared");
        assert!(
            names.contains(&"cmake"),
            "cmake must be declared (tool_requires)"
        );
    }

    #[test]
    fn conanfile_txt_evidence_is_declared() {
        let ctx = fixture_ctx("conan");
        let out = ConanCataloger.catalog(&ctx).unwrap();
        for c in out
            .iter()
            .filter(|c| c.matching_method.starts_with("conanfile_"))
        {
            assert_eq!(
                top_rung(&c.evidence),
                Some(EvidenceKind::Declared),
                "{} must be Declared",
                c.name
            );
        }
    }

    // -----------------------------------------------------------------------
    // conanfile.py (Declared, static extraction)
    // -----------------------------------------------------------------------

    #[test]
    fn conanfile_py_extracts_class_attr_requires() {
        let ctx = fixture_ctx("conan");
        let out = ConanCataloger.catalog(&ctx).unwrap();
        let py_comps: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "conanfile_requires")
            .collect();
        let names: Vec<_> = py_comps.iter().map(|c| c.name.as_str()).collect();
        // fmt and poco come from conanfile.py.
        assert!(
            names.contains(&"fmt") || names.contains(&"poco"),
            "conanfile.py requires must be extracted: {:?}",
            names
        );
    }

    #[test]
    fn conanfile_py_multiline_requires_tuple_captures_all() {
        // requires = ( "fmt/10.1.1", "poco/1.12.4", "spdlog/1.13.0", )
        // spanning several lines — ALL entries must be captured (not just line 1).
        let ctx = fixture_ctx("conan");
        let out = ConanCataloger.catalog(&ctx).unwrap();
        let names: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "conanfile_requires")
            .map(|c| c.name.as_str())
            .collect();
        assert!(names.contains(&"fmt"), "fmt: {names:?}");
        assert!(names.contains(&"poco"), "poco: {names:?}");
        assert!(
            names.contains(&"spdlog"),
            "spdlog (3rd tuple line) must be captured: {names:?}"
        );
    }

    #[test]
    fn conanfile_py_python_requires_is_extracted() {
        let ctx = fixture_ctx("conan");
        let out = ConanCataloger.catalog(&ctx).unwrap();
        let pyreq = out
            .iter()
            .find(|c| c.name == "pyreq")
            .expect("python_requires pyreq must be extracted");
        assert_eq!(pyreq.matching_method, "conanfile_python_requires");
        assert_eq!(pyreq.version.as_deref(), Some("0.1.0"));
    }

    // -----------------------------------------------------------------------
    // PURL correctness
    // -----------------------------------------------------------------------

    #[test]
    fn conanfile_txt_purl_format() {
        let ctx = fixture_ctx("conan");
        let out = ConanCataloger.catalog(&ctx).unwrap();
        let boost = out
            .iter()
            .find(|c| c.name == "boost" && c.matching_method.starts_with("conanfile_"))
            .expect("boost must be present");
        let purl = boost.purl.as_deref().unwrap_or("");
        assert!(purl.starts_with("pkg:conan/"), "must be pkg:conan: {purl}");
        assert!(purl.contains("boost"), "must contain name: {purl}");
        assert!(purl.contains("1.83.0"), "must contain version: {purl}");
    }

    // -----------------------------------------------------------------------
    // Merge via merge_by_identity
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_and_lock_merge_to_one_component() {
        let ctx = fixture_ctx("conan");
        let raw = ConanCataloger.catalog(&ctx).unwrap();
        let merged = crate::merge_by_identity(raw);
        // zlib appears in both conan.lock and conanfile.txt.
        let zlib_entries: Vec<_> = merged
            .iter()
            .filter(|c| {
                c.purl.as_deref()
                    == Some("pkg:conan/zlib@1.3.1?rrev=06023034579559bb64357db3a53f88a4")
            })
            .collect();
        assert_eq!(
            zlib_entries.len(),
            1,
            "zlib must collapse to 1 component after merge"
        );
    }

    // -----------------------------------------------------------------------
    // detect
    // -----------------------------------------------------------------------

    #[test]
    fn detect_true_for_conanfile_txt() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/conanfile.txt".into()]);
        assert!(ConanCataloger.detect(&ctx));
    }

    #[test]
    fn detect_true_for_conan_lock() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/conan.lock".into()]);
        assert!(ConanCataloger.detect(&ctx));
    }

    #[test]
    fn detect_false_without_conan_files() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/Cargo.toml".into()]);
        assert!(!ConanCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // parse_lock_ref unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn lock_ref_strips_timestamp() {
        let entry = parse_lock_ref(
            "zlib/1.3.1#06023034579559bb64357db3a53f88a4%1692672087.099",
            "conan.lock",
        )
        .unwrap();
        assert_eq!(entry.name, "zlib");
        assert_eq!(entry.version, "1.3.1");
        assert_eq!(
            entry.rrev.as_deref(),
            Some("06023034579559bb64357db3a53f88a4")
        );
    }

    #[test]
    fn lock_ref_parses_user_channel() {
        let entry = parse_lock_ref(
            "openssl/3.0.3@bincrafters/stable#93a82349c31917d%1675294635.604",
            "conan.lock",
        )
        .unwrap();
        assert_eq!(entry.name, "openssl");
        assert_eq!(entry.version, "3.0.3");
        assert_eq!(entry.user.as_deref(), Some("bincrafters"));
        assert_eq!(entry.channel.as_deref(), Some("stable"));
        assert_eq!(entry.rrev.as_deref(), Some("93a82349c31917d"));
    }

    #[test]
    fn lock_ref_no_rrev() {
        let entry = parse_lock_ref("poco/1.12.4", "conan.lock").unwrap();
        assert_eq!(entry.name, "poco");
        assert_eq!(entry.version, "1.12.4");
        assert!(entry.rrev.is_none());
    }
}
