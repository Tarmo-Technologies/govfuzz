// SPDX-License-Identifier: Apache-2.0

//! Tier-A C/C++ deep-extraction cataloger (`SourceObserved`).
//!
//! Scans `.c/.h/.cc/.cpp/.cxx/.hpp/.hh` files for `#include <...>` / `"..."`
//! directives and maps each included header against a bundled
//! native-component knowledge base (`data/native_components.toml`, embedded at
//! compile time via `include_str!`). A matched library becomes a
//! `SourceObserved` component with `ecosystem = "c"`.
//!
//! The KB supplies **identity only** (name / CPE / version-macro hint). Versions
//! are never invented: when a matching header is *vendored* in the scanned tree
//! (a `files` entry whose leaf equals the KB-named version header), the file is
//! read and the canonical `#define MACRO "x.y.z"` is extracted, yielding an
//! exact version for projects that have no manifest at all. A system-only
//! include (no vendored header) yields a version-unknown `SourceObserved`
//! component with no `@version` PURL.
//!
//! # Untrusted input
//! All files are size-bounded (≤4 MiB). Line scanning is bounded; block comments
//! are tracked cheaply so a commented-out `#include` is ignored. Parsing never
//! panics, never recurses unboundedly, and never touches the network.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::Component;
use crate::evidence::{Evidence, EvidenceKind};
use crate::license::{classify_license_text, spdx_license_id};
use crate::purl;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

/// The knowledge base, embedded at compile time. Parsed once on first use.
const KB_TOML: &str = include_str!("../../data/native_components.toml");

/// C/C++ source file extensions we scan for includes.
const C_EXTENSIONS: &[&str] = &["c", "h", "cc", "cpp", "cxx", "hpp", "hh"];

pub struct CSourceCataloger;

impl Cataloger for CSourceCataloger {
    fn ecosystem(&self) -> &str {
        "c"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files.iter().any(|p| is_c_source(p))
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let kb = kb();

        // Index vendored headers present in the tree: leaf name → path. Used to
        // read version macros from a header that ships inside the scanned tree.
        let mut vendored: BTreeMap<String, &Path> = BTreeMap::new();
        for path in &ctx.files {
            if let Some(leaf) = leaf_name(path) {
                vendored
                    .entry(leaf.to_ascii_lowercase())
                    .or_insert(path.as_path());
            }
        }

        // Every source path in the tree, normalized to `/`-joined lowercase, so an
        // `#include <dir/hdr.h>` can be tested for "resolves to a file in THIS
        // tree" (the user's own header, or a vendored copy) vs "referenced but not
        // present" (an external system/third-party dependency).
        let tree_paths: Vec<String> = ctx
            .files
            .iter()
            .map(|p| relative_path(&ctx.root, p).to_ascii_lowercase())
            .collect();

        // Accumulate one entry per matched library (by KB index), unioning the
        // evidence locators from every source file/line that includes it.
        let mut acc: BTreeMap<usize, Vec<String>> = BTreeMap::new();
        // External libraries NOT in the KB, keyed by their include's top-level
        // directory (`openssl/ssl.h` → `openssl`). These are the COTS/OSS/GOTS
        // dependencies a manifest-less tree references but never vendors — the KB
        // can't name a version for them, but they still belong in the SBOM.
        let mut ext_acc: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for path in ctx.files.iter().filter(|p| is_c_source(p)) {
            let rel = relative_path(&ctx.root, path);
            let source = read_bounded(path)?;
            for (line_no, include) in scan_includes(&source) {
                let locator = || format!("{rel}:{line_no} #include {}", include.render());
                if let Some(idx) = kb.match_header(&include.path) {
                    let locators = acc.entry(idx).or_default();
                    let loc = locator();
                    if !locators.contains(&loc) {
                        locators.push(loc);
                    }
                } else if let Some(name) = external_library_name(&include, &tree_paths) {
                    let locators = ext_acc.entry(name).or_default();
                    let loc = locator();
                    if !locators.contains(&loc) {
                        locators.push(loc);
                    }
                }
            }
        }

        let mut out = Vec::with_capacity(acc.len() + ext_acc.len());
        for (idx, locators) in acc {
            let lib = &kb.libraries[idx];
            let version = extract_version(lib, &vendored);
            let license = extract_license(lib, &vendored);
            out.push(make_component(lib, version, license, &locators));
        }
        for (name, locators) in ext_acc {
            out.push(make_external_component(&name, &locators));
        }
        Ok(out)
    }
}

/// Directory prefixes of a `<dir/hdr.h>` angle include that name the compiler /
/// OS platform, never a distributable third-party dependency. An include under
/// one of these is the toolchain or kernel UAPI, so it must NOT become an SBOM
/// component.
const SYSTEM_INCLUDE_DIRS: &[&str] = &[
    "sys",
    "bits",
    "gnu",
    "asm",
    "asm-generic",
    "linux",
    "uapi",
    "machine",
    "arpa",
    "net",
    "netinet",
    "netpacket",
    "rpc",
    "rpcsvc",
    "scsi",
    "mtd",
    "sound",
    "video",
    "xen",
    "drm",
    "c++",
    "arm",
    "arm64",
    "x86",
    "x86_64",
    "mach",
    "objc",
];

/// Generic project-layout directory names that a `<dir/hdr.h>` include may use
/// for the project's OWN headers (via a `-Iinclude`-style flag), so a
/// tree-relative resolution would miss them. Never a third-party library name.
const OWN_LAYOUT_DIRS: &[&str] = &[
    "include", "includes", "inc", "src", "source", "sources", "lib", "libs", "common", "core",
    "internal", "private", "public", "detail", "details", "impl", "util", "utils", "config",
];

/// The name of the EXTERNAL library an `#include` names, or `None` when the
/// include is the user's own source, a system/toolchain header, or too ambiguous
/// to attribute. Only a `<dir/leaf.h>` angle include is considered — the
/// `<dir>` is the conventional library name (`openssl/ssl.h` → `openssl`,
/// `SDL2/SDL.h` → `SDL2`). Excluded: quote includes (local by convention),
/// bare `<foo.h>` (indistinguishable from a generated `config.h`), system
/// prefixes, generic own-layout dirs, and any include that RESOLVES to a file
/// already in the scanned tree (the user's own header or a vendored copy the KB
/// path already covers). Precision over recall: a real external dep referenced
/// as `<lib/...>` is caught; the bare-header long tail defers to the KB.
fn external_library_name(include: &Include, tree_paths: &[String]) -> Option<String> {
    if !include.angle {
        return None;
    }
    let path = include.path.trim().trim_start_matches("./");
    let (dir, _) = path.split_once('/')?;
    let dir_lower = dir.to_ascii_lowercase();
    if dir.is_empty()
        || SYSTEM_INCLUDE_DIRS.contains(&dir_lower.as_str())
        || OWN_LAYOUT_DIRS.contains(&dir_lower.as_str())
    {
        return None;
    }
    // A header that resolves to a file present in the tree is the project's own
    // (or a vendored copy the KB handles) — not an unlisted external dependency.
    let needle = path.to_ascii_lowercase();
    let in_tree = tree_paths
        .iter()
        .any(|p| p == &needle || p.ends_with(&format!("/{needle}")));
    if in_tree {
        return None;
    }
    Some(dir.to_owned())
}

/// A `SourceObserved` component for an EXTERNAL library found via a `<dir/...>`
/// include with no KB entry and no vendored copy: identity is the include
/// directory, version is unknown (never invented), confidence is `low`.
fn make_external_component(name: &str, locators: &[String]) -> Component {
    let evidence = locators
        .iter()
        .map(|loc| Evidence::new(EvidenceKind::SourceObserved, loc.clone()))
        .collect();
    Component {
        component_ref: String::new(),
        name: name.to_owned(),
        version: None,
        ecosystem: "c".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(format!("pkg:generic/{}", name.to_ascii_lowercase())),
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "low".to_owned(),
        matching_method: "c_source_include_external".to_owned(),
        evidence,
        runtime_harnesses: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Knowledge base
// ---------------------------------------------------------------------------

/// One KB library entry (identity only).
#[derive(Debug)]
struct KbLibrary {
    name: String,
    cpe: Option<String>,
    version: Option<VersionHint>,
    /// All KB header paths mapped to this library. Used as fallback locations to
    /// read version macros / license banners from when the named version header
    /// is not the one actually vendored (e.g. a v2 single-header amalgamation).
    headers: Vec<String>,
}

/// Where to read a library's version from a vendored header. The header leaf is
/// compared case-insensitively against vendored files.
#[derive(Debug)]
enum VersionHint {
    /// `#define <macro> "x.y.z"` — the macro whose string literal is the version.
    StringMacro {
        header_leaf: String,
        macro_name: String,
    },
    /// Split integer macros composed into `MAJOR.MINOR[.PATCH]` — the common
    /// C++ header-only shape (`#define X_VERSION_MAJOR 3`, … with no string).
    SplitMacros {
        header_leaf: String,
        major: String,
        minor: String,
        /// Optional — some libraries expose only `MAJOR.MINOR`.
        patch: Option<String>,
    },
}

impl VersionHint {
    fn header_leaf(&self) -> &str {
        match self {
            VersionHint::StringMacro { header_leaf, .. }
            | VersionHint::SplitMacros { header_leaf, .. } => header_leaf,
        }
    }
}

/// Parsed KB with a header-lookup acceleration map.
struct Kb {
    libraries: Vec<KbLibrary>,
    /// Exact header path (lowercased) → index into `libraries`.
    exact: BTreeMap<String, usize>,
    /// Glob entries: (dir-prefix lowercased ending in `/`, index).
    globs: Vec<(String, usize)>,
}

impl Kb {
    /// Match an included header path against the KB. Exact match first, then a
    /// leaf `*` glob (e.g. `openssl/*.h` matches `openssl/err.h`).
    fn match_header(&self, include: &str) -> Option<usize> {
        let key = include.trim().to_ascii_lowercase();
        if let Some(&idx) = self.exact.get(&key) {
            return Some(idx);
        }
        for (prefix, idx) in &self.globs {
            // `openssl/*.h` → prefix `openssl/`: the include must start with it,
            // contain no further `/` after the prefix (single directory level),
            // and end in `.h`.
            if let Some(rest) = key.strip_prefix(prefix.as_str()) {
                if !rest.contains('/') && key.ends_with(".h") {
                    return Some(*idx);
                }
            }
        }
        None
    }
}

fn kb() -> &'static Kb {
    static KB: OnceLock<Kb> = OnceLock::new();
    KB.get_or_init(|| parse_kb(KB_TOML))
}

/// Parse the embedded KB structurally (`toml::Value`) — no serde derive needed.
/// The KB is a trusted, in-tree asset; a parse failure is a build-time bug, so
/// this `expect`s. (Runtime untrusted input is the *scanned tree*, not the KB.)
fn parse_kb(text: &str) -> Kb {
    let root: toml::Value = toml::from_str(text).expect("native_components.toml must parse");
    let mut libraries = Vec::new();

    if let Some(tables) = root.get("library").and_then(|v| v.as_array()) {
        for t in tables {
            let Some(name) = t.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let cpe = t.get("cpe").and_then(|v| v.as_str()).map(|s| s.to_owned());
            let version = t.get("version").and_then(|v| {
                let header = v.get("header").and_then(|x| x.as_str())?;
                let header_leaf = leaf_of(header).to_ascii_lowercase();
                // Single quoted-string macro (`macro = "..."`) takes precedence;
                // otherwise the split-integer form (`major`/`minor`[/`patch`]).
                if let Some(macro_name) = v.get("macro").and_then(|x| x.as_str()) {
                    Some(VersionHint::StringMacro {
                        header_leaf,
                        macro_name: macro_name.to_owned(),
                    })
                } else {
                    let major = v.get("major").and_then(|x| x.as_str())?;
                    let minor = v.get("minor").and_then(|x| x.as_str())?;
                    let patch = v.get("patch").and_then(|x| x.as_str()).map(str::to_owned);
                    Some(VersionHint::SplitMacros {
                        header_leaf,
                        major: major.to_owned(),
                        minor: minor.to_owned(),
                        patch,
                    })
                }
            });
            let headers: Vec<String> = t
                .get("headers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str())
                        .map(|s| s.to_owned())
                        .collect()
                })
                .unwrap_or_default();

            let idx = libraries.len();
            libraries.push((
                KbLibrary {
                    name: name.to_owned(),
                    cpe,
                    version,
                    headers: headers.clone(),
                },
                headers,
                idx,
            ));
        }
    }

    let mut exact = BTreeMap::new();
    let mut globs = Vec::new();
    for (_lib, headers, idx) in &libraries {
        for header in headers {
            let h = header.trim().to_ascii_lowercase();
            if let Some(stripped) = h.strip_suffix("*.h") {
                globs.push((stripped.to_owned(), *idx));
            } else {
                exact.entry(h).or_insert(*idx);
            }
        }
    }

    Kb {
        libraries: libraries.into_iter().map(|(lib, _, _)| lib).collect(),
        exact,
        globs,
    }
}

/// The leaf of a `/`-joined header path (`openssl/opensslv.h` → `opensslv.h`).
fn leaf_of(header: &str) -> &str {
    header.rsplit('/').next().unwrap_or(header)
}

// ---------------------------------------------------------------------------
// Include scanning
// ---------------------------------------------------------------------------

/// One parsed `#include` directive.
struct Include {
    path: String,
    /// `true` for `<...>`, `false` for `"..."`.
    angle: bool,
}

impl Include {
    fn render(&self) -> String {
        if self.angle {
            format!("<{}>", self.path)
        } else {
            format!("\"{}\"", self.path)
        }
    }
}

/// Scan a source string for `#include` directives, skipping `/* ... */` block
/// comments and `//` line comments. Returns `(1-based line number, include)`.
/// Bounded, allocation-light, never panics.
fn scan_includes(source: &str) -> Vec<(usize, Include)> {
    let mut out = Vec::new();
    let mut in_block_comment = false;

    for (i, raw_line) in source.lines().enumerate() {
        let line_no = i + 1;
        // Strip block comments (possibly spanning lines) and a trailing `//`.
        let cleaned = strip_comments(raw_line, &mut in_block_comment);
        let trimmed = cleaned.trim_start();
        if !trimmed.starts_with('#') {
            continue;
        }
        // Allow whitespace between `#` and `include`: `#  include`.
        let after_hash = trimmed[1..].trim_start();
        let Some(rest) = after_hash.strip_prefix("include") else {
            continue;
        };
        let rest = rest.trim_start();
        if let Some(inc) = parse_include_target(rest) {
            out.push((line_no, inc));
        }
    }
    out
}

/// Parse the target of an `#include` line: `<path>` or `"path"`.
fn parse_include_target(rest: &str) -> Option<Include> {
    let bytes = rest.as_bytes();
    let (open, close, angle) = match bytes.first()? {
        b'<' => (b'<', b'>', true),
        b'"' => (b'"', b'"', false),
        _ => return None,
    };
    let _ = open;
    let inner = &rest[1..];
    let end = inner.find(close as char)?;
    let path = inner[..end].trim().to_owned();
    if path.is_empty() {
        return None;
    }
    Some(Include { path, angle })
}

/// Remove block (`/* */`) and line (`//`) comments from a single line, tracking
/// open block-comment state across lines. Returns the comment-free remainder.
fn strip_comments(line: &str, in_block: &mut bool) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < bytes.len() {
        if *in_block {
            if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            *in_block = true;
            i += 2;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            break; // rest of line is a comment
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Version extraction from vendored headers
// ---------------------------------------------------------------------------

/// Vendored header leaves to scan for `lib`, in priority order: the named
/// version header first (when the lib has a version hint), then every other KB
/// header for the lib that is vendored in the tree. De-duplicated, lowercased.
/// This lets a v2 single-header amalgamation (`catch.hpp`) stand in for a v3
/// split-layout version header (`catch_version_macros.hpp`) that is not vendored.
fn vendored_header_leaves<'a>(
    lib: &KbLibrary,
    vendored: &BTreeMap<String, &'a Path>,
) -> Vec<&'a Path> {
    let mut leaves: Vec<String> = Vec::new();
    if let Some(hint) = lib.version.as_ref() {
        leaves.push(hint.header_leaf().to_owned());
    }
    for h in &lib.headers {
        let leaf = leaf_of(h).to_ascii_lowercase();
        // Skip glob leaves (`*.h`) — they never name a concrete vendored file.
        if leaf.contains('*') || leaves.contains(&leaf) {
            continue;
        }
        leaves.push(leaf);
    }
    leaves
        .iter()
        .filter_map(|leaf| vendored.get(leaf).copied())
        .collect()
}

/// Extract an exact version for `lib` from a vendored copy of one of its
/// headers, if present in the tree. The named version header is tried first;
/// when it is not vendored (or carries no macros) the other vendored KB headers
/// for the lib are scanned as a fallback. Returns `None` when no vendored header
/// yields the macros — a system-only include stays unversioned.
fn extract_version(lib: &KbLibrary, vendored: &BTreeMap<String, &Path>) -> Option<String> {
    let hint = lib.version.as_ref()?;
    for path in vendored_header_leaves(lib, vendored) {
        let Ok(source) = read_bounded(path) else {
            continue;
        };
        if let Some(version) = extract_version_from(hint, &source) {
            return Some(version);
        }
    }
    None
}

/// Apply a `VersionHint` to one header's source text.
fn extract_version_from(hint: &VersionHint, source: &str) -> Option<String> {
    match hint {
        VersionHint::StringMacro { macro_name, .. } => extract_define_string(source, macro_name),
        VersionHint::SplitMacros {
            major,
            minor,
            patch,
            ..
        } => {
            // Compose MAJOR.MINOR[.PATCH] from integer #defines. MAJOR and MINOR
            // are required; PATCH is optional (some headers omit it).
            let major = extract_define_int(source, major)?;
            let minor = extract_define_int(source, minor)?;
            match patch.as_deref().and_then(|p| extract_define_int(source, p)) {
                Some(patch) => Some(format!("{major}.{minor}.{patch}")),
                None => Some(format!("{major}.{minor}")),
            }
        }
    }
}

/// Extract a license for `lib` from a vendored header it already reads (Bug #52):
/// an inline `SPDX-License-Identifier:` tag takes precedence, otherwise the
/// header banner is classified by distinctive license phrases. Scans the same
/// vendored headers used for version extraction. Returns `None` when no vendored
/// header carries a recognizable license (a system-only include stays unknown).
fn extract_license(lib: &KbLibrary, vendored: &BTreeMap<String, &Path>) -> Option<String> {
    for path in vendored_header_leaves(lib, vendored) {
        let Ok(source) = read_bounded(path) else {
            continue;
        };
        if let Some(id) = spdx_license_id(&source) {
            return Some(id);
        }
        if let Some(id) = classify_license_text(&source) {
            return Some(id);
        }
    }
    None
}

/// Find `#define <macro> <integer>` and return the decimal value. Tolerant of
/// leading whitespace and trailing comments; ignores non-integer `#define`s and
/// the macro-prefix-collision case (whitespace boundary). Never panics.
fn extract_define_int(source: &str, macro_name: &str) -> Option<u64> {
    for line in source.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix('#') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix("define") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix(macro_name) else {
            continue;
        };
        // The macro name must be followed by whitespace (not be a prefix of a
        // longer macro, e.g. FOO_MAJOR vs FOO_MAJOR_REV).
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let token: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(value) = token.parse::<u64>() {
            return Some(value);
        }
    }
    None
}

/// Find `#define <macro> "literal"` and return the literal. Tolerant of leading
/// whitespace and trailing comments; ignores non-string `#define`s. Never panics.
fn extract_define_string(source: &str, macro_name: &str) -> Option<String> {
    for line in source.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix('#') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix("define") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix(macro_name) else {
            continue;
        };
        // The macro name must be followed by whitespace (not be a prefix of a
        // longer macro, e.g. ZLIB_VERSION vs ZLIB_VERSION_NUM).
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let rest = rest.trim_start();
        let lit = first_string_literal(rest)?;
        if !lit.is_empty() {
            return Some(lit);
        }
    }
    None
}

/// Return the contents of the first double-quoted literal in `s`.
fn first_string_literal(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let rest = &s[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

// ---------------------------------------------------------------------------
// Component construction
// ---------------------------------------------------------------------------

fn make_component(
    lib: &KbLibrary,
    version: Option<String>,
    license: Option<String>,
    locators: &[String],
) -> Component {
    let purl = match &version {
        Some(v) => Some(purl::generic(&lib.name, v)),
        // No exact version → a bare `pkg:generic/<name>` with no `@version`.
        None => Some(format!("pkg:generic/{}", lib.name.to_ascii_lowercase())),
    };
    let confidence = if version.is_some() { "medium" } else { "low" };
    let evidence = locators
        .iter()
        .map(|loc| Evidence::new(EvidenceKind::SourceObserved, loc.clone()))
        .collect();
    Component {
        component_ref: String::new(),
        name: lib.name.clone(),
        version,
        ecosystem: "c".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license,
        purl,
        cpe: lib.cpe.clone(),
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: confidence.to_owned(),
        matching_method: "c_source_include".to_owned(),
        evidence,
        runtime_harnesses: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_c_source(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| C_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

fn leaf_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|n| n.to_str())
}

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
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
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
    // KB sanity
    // -----------------------------------------------------------------------

    #[test]
    fn kb_parses_and_has_seed_libraries() {
        let kb = kb();
        assert!(kb.libraries.len() >= 15, "expected ≥15 seeded libraries");
        let names: Vec<_> = kb.libraries.iter().map(|l| l.name.as_str()).collect();
        for expected in ["zlib", "openssl", "sqlite3", "curl", "zstd"] {
            assert!(
                names.contains(&expected),
                "KB missing {expected}: {names:?}"
            );
        }
    }

    #[test]
    fn kb_glob_matches_subdir_header() {
        let kb = kb();
        // openssl/*.h glob.
        let idx = kb.match_header("openssl/err.h").expect("glob must match");
        assert_eq!(kb.libraries[idx].name, "openssl");
        // exact still wins for the explicitly listed header.
        let idx2 = kb.match_header("openssl/ssl.h").expect("exact must match");
        assert_eq!(kb.libraries[idx2].name, "openssl");
    }

    #[test]
    fn kb_glob_does_not_match_deeper_path_or_non_h() {
        let kb = kb();
        assert!(kb.match_header("openssl/sub/deep.h").is_none());
        assert!(kb.match_header("openssl/ssl.cpp").is_none());
    }

    // -----------------------------------------------------------------------
    // Include scanning
    // -----------------------------------------------------------------------

    #[test]
    fn scan_finds_angle_and_quote_includes() {
        let src = "#include <zlib.h>\n#include \"local.h\"\n";
        let incs = scan_includes(src);
        assert_eq!(incs.len(), 2);
        assert_eq!(incs[0].1.path, "zlib.h");
        assert!(incs[0].1.angle);
        assert_eq!(incs[1].1.path, "local.h");
        assert!(!incs[1].1.angle);
    }

    #[test]
    fn scan_skips_commented_includes() {
        let src = "// #include <evil.h>\n/* #include <also_evil.h> */\n#include <zlib.h>\n";
        let incs = scan_includes(src);
        assert_eq!(incs.len(), 1, "only the live include counts");
        assert_eq!(incs[0].1.path, "zlib.h");
    }

    #[test]
    fn scan_skips_multiline_block_comment() {
        let src = "/* opening\n#include <hidden.h>\nstill comment */\n#include <zlib.h>\n";
        let incs = scan_includes(src);
        assert_eq!(incs.len(), 1);
        assert_eq!(incs[0].1.path, "zlib.h");
    }

    #[test]
    fn scan_allows_space_after_hash() {
        let src = "#  include   <zlib.h>\n";
        let incs = scan_includes(src);
        assert_eq!(incs.len(), 1);
        assert_eq!(incs[0].1.path, "zlib.h");
    }

    #[test]
    fn scan_does_not_panic_on_garbage() {
        for s in [
            "#include <",
            "#include \"",
            "#include",
            "###",
            "#include <>",
        ] {
            let _ = scan_includes(s); // must not panic
        }
    }

    // -----------------------------------------------------------------------
    // External (non-KB) include attribution
    // -----------------------------------------------------------------------

    fn angle(path: &str) -> Include {
        Include {
            path: path.to_owned(),
            angle: true,
        }
    }

    #[test]
    fn external_name_from_dir_prefixed_third_party_include() {
        // A `<lib/hdr.h>` not present in the tree is an external dependency named
        // by its top directory.
        let tree: Vec<String> = vec!["src/app.c".into()];
        assert_eq!(
            external_library_name(&angle("acmecorp/widget.h"), &tree),
            Some("acmecorp".to_owned())
        );
        assert_eq!(
            external_library_name(&angle("SDL2/SDL.h"), &tree),
            Some("SDL2".to_owned())
        );
    }

    #[test]
    fn external_name_excludes_own_system_and_ambiguous() {
        // Own header present in the tree -> not external.
        let tree: Vec<String> = vec!["src/app.c".into(), "src/myproj/util.h".into()];
        assert_eq!(external_library_name(&angle("myproj/util.h"), &tree), None);
        // System/toolchain prefix -> not a component.
        assert_eq!(external_library_name(&angle("sys/socket.h"), &tree), None);
        assert_eq!(external_library_name(&angle("bits/types.h"), &tree), None);
        // Generic own-layout dir -> not a component.
        assert_eq!(
            external_library_name(&angle("include/generated.h"), &tree),
            None
        );
        // Bare header (no dir) -> too ambiguous (could be a generated config.h).
        assert_eq!(external_library_name(&angle("config.h"), &tree), None);
        // Quote include -> local by convention, never external.
        assert_eq!(
            external_library_name(
                &Include {
                    path: "vendor/thing.h".into(),
                    angle: false
                },
                &tree
            ),
            None
        );
    }

    #[test]
    fn external_name_resolves_in_tree_by_path_suffix() {
        // A vendored copy present deeper in the tree resolves as in-tree (the KB
        // path handles known vendored libs), so it is not re-listed as unknown.
        let tree: Vec<String> = vec!["third_party/zlib/zlib.h".into()];
        assert_eq!(external_library_name(&angle("zlib/zlib.h"), &tree), None);
    }

    // -----------------------------------------------------------------------
    // Version extraction
    // -----------------------------------------------------------------------

    #[test]
    fn extract_define_reads_string_literal() {
        let src = "#define ZLIB_VERSION \"1.3.1\"\n";
        assert_eq!(
            extract_define_string(src, "ZLIB_VERSION").as_deref(),
            Some("1.3.1")
        );
    }

    #[test]
    fn extract_define_ignores_macro_prefix_collision() {
        // ZLIB_VERSION must not match ZLIB_VERSION_NUM (whitespace boundary).
        let src = "#define ZLIB_VERSION_NUM 0x1310\n#define ZLIB_VERSION \"1.3.1\"\n";
        assert_eq!(
            extract_define_string(src, "ZLIB_VERSION").as_deref(),
            Some("1.3.1")
        );
    }

    #[test]
    fn extract_define_absent_macro_is_none() {
        let src = "#define SOMETHING_ELSE 1\n";
        assert!(extract_define_string(src, "ZLIB_VERSION").is_none());
    }

    #[test]
    fn extract_define_int_reads_integer_macros() {
        let src = "#define NLOHMANN_JSON_VERSION_MAJOR 3 // major\n\
                   #define NLOHMANN_JSON_VERSION_MINOR 11\n\
                   #define NLOHMANN_JSON_VERSION_PATCH 3\n";
        assert_eq!(
            extract_define_int(src, "NLOHMANN_JSON_VERSION_MAJOR"),
            Some(3)
        );
        assert_eq!(
            extract_define_int(src, "NLOHMANN_JSON_VERSION_MINOR"),
            Some(11)
        );
        assert_eq!(
            extract_define_int(src, "NLOHMANN_JSON_VERSION_PATCH"),
            Some(3)
        );
        assert_eq!(extract_define_int(src, "ABSENT"), None);
    }

    #[test]
    fn split_version_macros_compose_dotted_version() {
        // nlohmann/json exposes split integer macros (no quoted-string version).
        let (_d, ctx) = temp_ctx(&[
            ("main.cpp", "#include <nlohmann/json.hpp>\n"),
            (
                "json.hpp",
                "#define NLOHMANN_JSON_VERSION_MAJOR 3\n\
                 #define NLOHMANN_JSON_VERSION_MINOR 11\n\
                 #define NLOHMANN_JSON_VERSION_PATCH 3\n",
            ),
        ]);
        let out = CSourceCataloger.catalog(&ctx).unwrap();
        let nl = out
            .iter()
            .find(|c| c.name == "nlohmann-json")
            .expect("nlohmann-json must be SourceObserved");
        assert_eq!(nl.version.as_deref(), Some("3.11.3"));
        assert_eq!(nl.purl.as_deref(), Some("pkg:generic/nlohmann-json@3.11.3"));
    }

    #[test]
    fn catch2_split_macros_resolve_from_version_header() {
        let (_d, ctx) = temp_ctx(&[
            ("test.cpp", "#include <catch2/catch_test_macros.hpp>\n"),
            (
                "catch_version_macros.hpp",
                "#define CATCH_VERSION_MAJOR 3\n#define CATCH_VERSION_MINOR 5\n#define CATCH_VERSION_PATCH 2\n",
            ),
        ]);
        let out = CSourceCataloger.catalog(&ctx).unwrap();
        let catch = out
            .iter()
            .find(|c| c.name == "catch2")
            .expect("catch2 must be SourceObserved");
        assert_eq!(catch.version.as_deref(), Some("3.5.2"));
    }

    #[test]
    fn catch2_v2_single_header_resolves_version_from_amalgamation() {
        // Bug #54: catch2 v2 ships a single `catch.hpp` carrying the version
        // macros; the KB's named version header (catch_version_macros.hpp, the v3
        // split layout) is NOT vendored. Fall back to scanning the matched header.
        let (_d, ctx) = temp_ctx(&[
            ("test.cpp", "#include <catch.hpp>\n"),
            (
                "catch.hpp",
                "/* Catch v2.13.10 */\n#define CATCH_VERSION_MAJOR 2\n\
                 #define CATCH_VERSION_MINOR 13\n#define CATCH_VERSION_PATCH 10\n",
            ),
        ]);
        let out = CSourceCataloger.catalog(&ctx).unwrap();
        let catch = out
            .iter()
            .find(|c| c.name == "catch2")
            .expect("catch2 must be SourceObserved");
        assert_eq!(catch.version.as_deref(), Some("2.13.10"));
        assert_eq!(catch.purl.as_deref(), Some("pkg:generic/catch2@2.13.10"));
    }

    // -----------------------------------------------------------------------
    // License extraction from a vendored header (Bug #52)
    // -----------------------------------------------------------------------

    #[test]
    fn vendored_header_spdx_identifier_sets_license() {
        // Bug #52: an inline SPDX-License-Identifier in the vendored header that
        // the cataloger already reads must populate the component license.
        let (_d, ctx) = temp_ctx(&[
            ("main.cpp", "#include <nlohmann/json.hpp>\n"),
            (
                "json.hpp",
                "// SPDX-License-Identifier: MIT\n#define NLOHMANN_JSON_VERSION_MAJOR 3\n\
                 #define NLOHMANN_JSON_VERSION_MINOR 11\n#define NLOHMANN_JSON_VERSION_PATCH 3\n",
            ),
        ]);
        let out = CSourceCataloger.catalog(&ctx).unwrap();
        let nl = out
            .iter()
            .find(|c| c.name == "nlohmann-json")
            .expect("nlohmann-json present");
        assert_eq!(nl.license.as_deref(), Some("MIT"));
    }

    #[test]
    fn vendored_header_license_banner_is_classified() {
        // Bug #52: no SPDX line, but a recognizable license banner — classify it
        // (catch2's amalgamation carries a Boost Software License banner).
        let (_d, ctx) = temp_ctx(&[
            ("test.cpp", "#include <catch.hpp>\n"),
            (
                "catch.hpp",
                "/*\n * Distributed under the Boost Software License, Version 1.0.\n */\n\
                 #define CATCH_VERSION_MAJOR 2\n#define CATCH_VERSION_MINOR 13\n\
                 #define CATCH_VERSION_PATCH 10\n",
            ),
        ]);
        let out = CSourceCataloger.catalog(&ctx).unwrap();
        let catch = out
            .iter()
            .find(|c| c.name == "catch2")
            .expect("catch2 present");
        assert_eq!(catch.license.as_deref(), Some("BSL-1.0"));
    }

    #[test]
    fn system_only_include_has_no_license() {
        // Without a vendored header there is nothing to read; license stays None.
        let ctx = fixture_ctx("c_source");
        let out = CSourceCataloger.catalog(&ctx).unwrap();
        let sqlite = out.iter().find(|c| c.name == "sqlite3").unwrap();
        assert!(sqlite.license.is_none());
    }

    // -----------------------------------------------------------------------
    // detect
    // -----------------------------------------------------------------------

    #[test]
    fn detect_true_for_c_files() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/main.c".into()]);
        assert!(CSourceCataloger.detect(&ctx));
        let cpp = CatalogContext::new("/r".into(), vec!["/r/app.cpp".into()]);
        assert!(CSourceCataloger.detect(&cpp));
    }

    #[test]
    fn detect_false_without_c_files() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/Cargo.toml".into()]);
        assert!(!CSourceCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // End-to-end against the c_source fixture
    // -----------------------------------------------------------------------

    #[test]
    fn vendored_header_yields_exact_version() {
        let ctx = fixture_ctx("c_source");
        let out = CSourceCataloger.catalog(&ctx).unwrap();
        let zlib = out
            .iter()
            .find(|c| c.name == "zlib")
            .expect("zlib must be SourceObserved");
        assert_eq!(zlib.version.as_deref(), Some("1.3.1"));
        assert_eq!(zlib.purl.as_deref(), Some("pkg:generic/zlib@1.3.1"));
        assert_eq!(zlib.ecosystem, "c");
        assert_eq!(zlib.component_type, "library");
        assert_eq!(top_rung(&zlib.evidence), Some(EvidenceKind::SourceObserved));
        assert!(
            zlib.evidence[0].source.contains("main.c"),
            "evidence locator must reference the including file: {:?}",
            zlib.evidence
        );
        assert!(zlib.evidence[0].source.contains("#include <zlib.h>"));
    }

    #[test]
    fn system_only_include_is_version_unknown() {
        let ctx = fixture_ctx("c_source");
        let out = CSourceCataloger.catalog(&ctx).unwrap();
        let sqlite = out
            .iter()
            .find(|c| c.name == "sqlite3")
            .expect("sqlite3 must be SourceObserved");
        assert!(sqlite.version.is_none(), "no vendored header → no version");
        assert_eq!(sqlite.purl.as_deref(), Some("pkg:generic/sqlite3"));
        assert_eq!(
            top_rung(&sqlite.evidence),
            Some(EvidenceKind::SourceObserved)
        );
    }

    #[test]
    fn unknown_header_yields_no_component() {
        let ctx = fixture_ctx("c_source");
        let out = CSourceCataloger.catalog(&ctx).unwrap();
        assert!(
            !out.iter().any(|c| c.name.contains("nonexistent")),
            "unknown header must not produce a component"
        );
        // Only the two KB libraries reachable from the fixture.
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"zlib"));
        assert!(names.contains(&"sqlite3"));
    }

    #[test]
    fn library_included_from_many_files_dedups_to_one_component() {
        let (_d, ctx) = temp_ctx(&[
            ("a.c", "#include <zlib.h>\n"),
            ("b.c", "#include <zlib.h>\n"),
            ("zlib.h", "#define ZLIB_VERSION \"1.2.13\"\n"),
        ]);
        let out = CSourceCataloger.catalog(&ctx).unwrap();
        let zlibs: Vec<_> = out.iter().filter(|c| c.name == "zlib").collect();
        assert_eq!(zlibs.len(), 1, "one component despite two includes");
        // Union of locators from both files.
        assert_eq!(zlibs[0].evidence.len(), 2);
        assert_eq!(zlibs[0].version.as_deref(), Some("1.2.13"));
    }

    // -----------------------------------------------------------------------
    // Merge with a Declared component of the same identity
    // -----------------------------------------------------------------------

    #[test]
    fn source_observed_merges_with_declared_zlib() {
        // A SourceObserved zlib@1.3.1 (from C source) and a Declared zlib@1.3.1
        // (from a conan/generic manifest) share the same purl → collapse to one
        // component carrying both rungs, top rung = SourceObserved.
        let (_d, ctx) = temp_ctx(&[
            ("main.c", "#include <zlib.h>\n"),
            ("zlib.h", "#define ZLIB_VERSION \"1.3.1\"\n"),
        ]);
        let mut all = CSourceCataloger.catalog(&ctx).unwrap();

        let declared = Component {
            component_ref: String::new(),
            name: "zlib".to_owned(),
            version: Some("1.3.1".to_owned()),
            ecosystem: "c".to_owned(),
            group: None,
            component_type: "library".to_owned(),
            supplier: None,
            license: None,
            purl: Some("pkg:generic/zlib@1.3.1".to_owned()),
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "low".to_owned(),
            matching_method: "conanfile_requires".to_owned(),
            evidence: vec![Evidence::new(EvidenceKind::Declared, "conanfile.txt:zlib")],
            runtime_harnesses: Vec::new(),
        };
        all.push(declared);

        let merged = crate::merge_by_identity(all);
        let zlibs: Vec<_> = merged
            .iter()
            .filter(|c| c.purl.as_deref() == Some("pkg:generic/zlib@1.3.1"))
            .collect();
        assert_eq!(zlibs.len(), 1, "SourceObserved + Declared collapse to one");
        let z = zlibs[0];
        assert!(z.evidence.iter().any(|e| e.kind == EvidenceKind::Declared));
        assert!(z
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::SourceObserved));
        assert_eq!(
            top_rung(&z.evidence),
            Some(EvidenceKind::SourceObserved),
            "SourceObserved is the higher rung"
        );
    }
}
