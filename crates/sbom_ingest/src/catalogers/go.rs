// SPDX-License-Identifier: Apache-2.0

//! Go modules cataloger.
//!
//! **Declared+Resolved (direct)**: `go.mod` — MVS pins one version per module,
//! so every `require` entry is both declared and already resolved for direct
//! deps. Emitted as `Resolved` (exact version, no hash from go.mod itself).
//! **Resolved (full transitive + dirhash)**: `go.sum` — lines carry the `h1:`
//! base64-encoded dirhash. Per the spec: `h1:` is a SHA-256 of a sorted tree
//! manifest (not a raw tarball SHA-256), so it MUST NOT be stored in `hashes[]`
//! as a plain SHA-256 `HashRef`. Instead it is recorded as an Evidence note.
//!
//! # PURL
//! `pkg:golang/<module-path>@<version>` — case preserved (recommended; Syft/cdxgen
//! real behavior; disputed but spec text conflicts with case-sensitive resolution).
//! `/` separators are NOT percent-encoded. Leading `v` kept in version.
//!
//! # Merge strategy
//! go.mod emits Resolved components with the exact PURL; go.sum entries are
//! additional corroborating evidence. `merge_by_identity` collapses them via
//! `ComponentKey::Purl`.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::Component;
use crate::evidence::{Evidence, EvidenceKind};
use crate::license::classify_license_text;
use crate::purl;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct GoCataloger;

impl Cataloger for GoCataloger {
    fn ecosystem(&self) -> &str {
        "golang"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("go.mod").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();

        // Build a module-path → GoModEntry index from go.mod(s).
        let mut mod_index: HashMap<String, GoModEntry> = HashMap::new();

        for path in ctx.files_named("go.mod") {
            let rel = relative_path(&ctx.root, path);
            // The module's OWN identity (the BOM's primary subject), tagged
            // `source` so governance can adopt it as metadata.component. Its
            // license is classified from a sibling LICENSE/COPYING file.
            if let Some(self_component) = parse_go_mod_self_component(path, &rel, ctx)? {
                out.push(self_component);
            }
            for entry in parse_go_mod(path, &rel)? {
                mod_index
                    .entry(entry.module_path.clone())
                    .or_insert_with(|| entry.clone());
                out.push(gomod_component(entry));
            }
        }

        // go.sum: corroborating h1: dirhash evidence. One note per module per
        // non-`/go.mod` sum line (the zip-tree line, not the go.mod-only line).
        for path in ctx.files_named("go.sum") {
            let rel = relative_path(&ctx.root, path);
            for sum in parse_go_sum(path, &rel)? {
                // Only the `h1:<base64>=` (zip-tree) line, not `/go.mod` lines.
                if sum.is_gomod_only {
                    continue;
                }
                // Find the matching go.mod component and attach the dirhash note.
                if let Some(comp) = out.iter_mut().find(|c| {
                    c.ecosystem == "golang"
                        && c.name == sum.module_path
                        && c.version.as_deref() == Some(sum.version.as_str())
                }) {
                    comp.evidence.push(Evidence {
                        kind: EvidenceKind::Resolved,
                        source: format!("{}:{} {}", sum.relative, sum.module_path, sum.version),
                        locator: Some(format!("h1:{}", sum.h1_b64)),
                    });
                } else if !mod_index.contains_key(&sum.module_path) {
                    // go.sum entry for a module not in go.mod (old/pruned graph) →
                    // still emit it as Resolved without a go.mod backing.
                    out.push(gosum_only_component(&sum));
                }
            }
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Internal data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct GoModEntry {
    module_path: String,
    version: String,
    is_indirect: bool,
    relative: String,
}

#[derive(Debug, Clone)]
struct GoSumEntry {
    module_path: String,
    version: String,
    h1_b64: String,
    is_gomod_only: bool,
    relative: String,
}

fn gomod_component(entry: GoModEntry) -> Component {
    // A local-path replacement (`=> ./local`) leaves an empty version: emit the
    // component source-only (no version, no PURL) so identity never treats the
    // missing pin as a version.
    let has_version = !entry.version.is_empty();
    let purl_val = if has_version {
        Some(purl::golang(&entry.module_path, &entry.version))
    } else {
        None
    };
    let source = format!(
        "{}:{} {}{}",
        entry.relative,
        entry.module_path,
        entry.version,
        if entry.is_indirect {
            " // indirect"
        } else {
            ""
        }
    );
    Component {
        component_ref: String::new(),
        name: entry.module_path,
        version: if has_version {
            Some(entry.version)
        } else {
            None
        },
        ecosystem: "golang".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: purl_val,
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "high".to_owned(),
        matching_method: "go_mod".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Resolved, source)],
        runtime_harnesses: Vec::new(),
    }
}

fn gosum_only_component(sum: &GoSumEntry) -> Component {
    let purl_val = purl::golang(&sum.module_path, &sum.version);
    let source = format!("{}:{} {}", sum.relative, sum.module_path, sum.version);
    Component {
        component_ref: String::new(),
        name: sum.module_path.clone(),
        version: Some(sum.version.clone()),
        ecosystem: "golang".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(purl_val),
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "medium".to_owned(),
        matching_method: "go_sum".to_owned(),
        evidence: vec![Evidence {
            kind: EvidenceKind::Resolved,
            source,
            locator: Some(format!("h1:{}", sum.h1_b64)),
        }],
        runtime_harnesses: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// go.mod parser
// ---------------------------------------------------------------------------

fn parse_go_mod(path: &Path, relative: &str) -> Result<Vec<GoModEntry>, CatalogError> {
    let source = read_to_string(path)?;
    let mut requires = Vec::new();
    let mut replaces: Vec<ReplaceDirective> = Vec::new();
    let mut excludes: Vec<(String, String)> = Vec::new();

    // Which factored block we are currently inside, if any.
    #[derive(PartialEq)]
    enum Block {
        None,
        Require,
        Replace,
        Exclude,
    }
    let mut block = Block::None;

    for line in source.lines() {
        let line = line.trim();

        // Skip comments.
        if line.starts_with("//") {
            continue;
        }

        // Close a factored block.
        if line == ")" && block != Block::None {
            block = Block::None;
            continue;
        }

        // Open a factored block.
        if line == "require (" {
            block = Block::Require;
            continue;
        }
        if line == "replace (" {
            block = Block::Replace;
            continue;
        }
        if line == "exclude (" {
            block = Block::Exclude;
            continue;
        }

        // Single-line directives.
        if let Some(rest) = line.strip_prefix("require ") {
            if let Some(entry) = parse_require_line(rest.trim(), relative) {
                requires.push(entry);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("replace ") {
            if let Some(r) = parse_replace_line(rest.trim()) {
                replaces.push(r);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("exclude ") {
            if let Some(e) = parse_exclude_line(rest.trim()) {
                excludes.push(e);
            }
            continue;
        }

        // Inside a factored block.
        if !line.is_empty() {
            match block {
                Block::Require => {
                    if let Some(entry) = parse_require_line(line, relative) {
                        requires.push(entry);
                    }
                }
                Block::Replace => {
                    if let Some(r) = parse_replace_line(line) {
                        replaces.push(r);
                    }
                }
                Block::Exclude => {
                    if let Some(e) = parse_exclude_line(line) {
                        excludes.push(e);
                    }
                }
                Block::None => {}
            }
        }

        // Skip module / go / toolchain directives (nothing to emit).
    }

    Ok(apply_replace_exclude(
        requires, &replaces, &excludes, relative,
    ))
}

/// A parsed `replace` directive: `old[ vX] => new[ vY]` or `=> ./local`.
#[derive(Debug, Clone)]
struct ReplaceDirective {
    old_path: String,
    /// `Some(version)` when the directive pins the old version; `None` matches any.
    old_version: Option<String>,
    new_path: String,
    /// `None` for a local-path replacement (`=> ./local`, `=> /abs`) — no version.
    new_version: Option<String>,
}

/// Parse the RHS of a single `replace` (everything after `replace `, or a block line):
/// `<old>[ <oldver>] => <new>[ <newver>]`.
fn parse_replace_line(line: &str) -> Option<ReplaceDirective> {
    let (lhs, rhs) = line.split_once("=>")?;
    let mut left = lhs.split_whitespace();
    let old_path = left.next()?.to_owned();
    let old_version = left.next().map(str::to_owned);

    let mut right = rhs.split_whitespace();
    let new_path = right.next()?.to_owned();
    // A local-path replacement (`./local`, `../x`, `/abs`) has no version.
    let is_local = new_path.starts_with('.') || new_path.starts_with('/');
    let new_version = if is_local {
        None
    } else {
        right.next().map(str::to_owned)
    };

    Some(ReplaceDirective {
        old_path,
        old_version,
        new_path,
        new_version,
    })
}

/// Parse a single `exclude` directive line: `<path> <version>`.
fn parse_exclude_line(line: &str) -> Option<(String, String)> {
    let mut toks = line.split_whitespace();
    let path = toks.next()?.to_owned();
    let version = toks.next()?.to_owned();
    Some((path, version))
}

/// Apply `replace`/`exclude` directives to the `require` set (main module only —
/// directives in a go.mod only affect that module's own build).
fn apply_replace_exclude(
    requires: Vec<GoModEntry>,
    replaces: &[ReplaceDirective],
    excludes: &[(String, String)],
    relative: &str,
) -> Vec<GoModEntry> {
    let mut out = Vec::new();
    for entry in requires {
        // Drop excluded (path, version) pairs.
        if excludes
            .iter()
            .any(|(p, v)| *p == entry.module_path && *v == entry.version)
        {
            continue;
        }

        // Find a matching replace: same path AND (no old version OR matching old version).
        if let Some(r) = replaces.iter().find(|r| {
            r.old_path == entry.module_path
                && r.old_version
                    .as_ref()
                    .map(|v| v == &entry.version)
                    .unwrap_or(true)
        }) {
            match &r.new_version {
                // `=> new vY`: redirect to the replacement coordinate.
                Some(new_version) => out.push(GoModEntry {
                    module_path: r.new_path.clone(),
                    version: new_version.clone(),
                    is_indirect: entry.is_indirect,
                    relative: relative.to_owned(),
                }),
                // `=> ./local`: source-only, no version/hash.
                None => out.push(GoModEntry {
                    module_path: entry.module_path,
                    version: String::new(),
                    is_indirect: entry.is_indirect,
                    relative: relative.to_owned(),
                }),
            }
            continue;
        }

        out.push(entry);
    }
    out
}

/// Parse a single require line: `<module-path> <version> [// indirect]`.
/// Returns None for empty lines, local replaces (`./...`), or malformed input.
fn parse_require_line(line: &str, relative: &str) -> Option<GoModEntry> {
    // Strip inline `//` comment to detect `// indirect`.
    let (code_part, comment) = split_go_comment(line);
    let is_indirect = comment
        .as_deref()
        .map(|c| c.trim().starts_with("indirect"))
        .unwrap_or(false);

    let mut tokens = code_part.split_whitespace();
    let module_path = tokens.next()?;
    let version = tokens.next()?;

    // Skip local path replaces (versions starting with `.` or `/`).
    if version.starts_with('.') || version.starts_with('/') {
        return None;
    }
    // Sanity: version must start with `v` or be a `v0.0.0-` pseudo-version.
    if !version.starts_with('v') {
        return None;
    }

    Some(GoModEntry {
        module_path: module_path.to_owned(),
        version: version.to_owned(),
        is_indirect,
        relative: relative.to_owned(),
    })
}

/// Split `line` into (code, optional_comment) where comment is the text after `//`.
fn split_go_comment(line: &str) -> (String, Option<String>) {
    if let Some(pos) = line.find("//") {
        let code = line[..pos].trim().to_owned();
        let comment = line[pos + 2..].trim().to_owned();
        (
            code,
            if comment.is_empty() {
                None
            } else {
                Some(comment)
            },
        )
    } else {
        (line.trim().to_owned(), None)
    }
}

// ---------------------------------------------------------------------------
// go.sum parser
// ---------------------------------------------------------------------------

fn parse_go_sum(path: &Path, relative: &str) -> Result<Vec<GoSumEntry>, CatalogError> {
    let source = read_to_string(path)?;
    let mut out = Vec::new();

    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        // Format: `<module-path> <ver>[/go.mod] h1:<base64>=`
        let mut parts = line.splitn(3, ' ');
        let module_path = match parts.next() {
            Some(p) if !p.is_empty() => p,
            _ => continue,
        };
        let ver_field = match parts.next() {
            Some(v) if !v.is_empty() => v,
            _ => continue,
        };
        let hash_field = match parts.next() {
            Some(h) if h.starts_with("h1:") => h,
            _ => continue,
        };

        // Detect `/go.mod`-only entries.
        let (version, is_gomod_only) = if let Some(v) = ver_field.strip_suffix("/go.mod") {
            (v.to_owned(), true)
        } else {
            (ver_field.to_owned(), false)
        };

        // Extract the base64 payload (everything after `h1:`, may have trailing `=`).
        let h1_b64 = hash_field["h1:".len()..].to_owned();

        out.push(GoSumEntry {
            module_path: module_path.to_owned(),
            version,
            h1_b64,
            is_gomod_only,
            relative: relative.to_owned(),
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Module self-component + LICENSE classification
// ---------------------------------------------------------------------------

/// Build the module's OWN component (the BOM's primary subject) from the `module`
/// directive in `go.mod`. go.mod carries no version for the module itself, so the
/// purl is the version-less `pkg:golang/<module>`. Its license is classified from
/// a sibling `LICENSE`/`COPYING` file when present. Tagged `component_type =
/// "source"` / `matching_method = "go_mod_project"` with root-relative `Declared`
/// evidence so governance can adopt it as `metadata.component`.
fn parse_go_mod_self_component(
    path: &Path,
    relative: &str,
    ctx: &CatalogContext,
) -> Result<Option<Component>, CatalogError> {
    let source = read_to_string(path)?;
    let Some(module_path) = parse_module_directive(&source) else {
        return Ok(None);
    };
    let license = module_license(ctx, path);
    Ok(Some(Component {
        component_ref: String::new(),
        name: module_path.clone(),
        group: None,
        version: None,
        ecosystem: "golang".to_owned(),
        component_type: "source".to_owned(),
        supplier: None,
        license,
        purl: Some(purl::golang_nameonly(&module_path)),
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "high".to_owned(),
        matching_method: "go_mod_project".to_owned(),
        evidence: vec![Evidence::new(EvidenceKind::Declared, relative.to_owned())],
        runtime_harnesses: Vec::new(),
    }))
}

/// Extract the module path from the `module <path>` directive (the path may be
/// double-quoted). Returns `None` when absent or malformed.
fn parse_module_directive(source: &str) -> Option<String> {
    for line in source.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("module ") {
            // Drop an inline comment, then trim optional surrounding quotes.
            let rest = rest.split("//").next().unwrap_or(rest).trim();
            let rest = rest.trim_matches('"').trim();
            if !rest.is_empty() {
                return Some(rest.to_owned());
            }
        }
    }
    None
}

/// Classify the SPDX license of the module from a sibling `LICENSE`/`COPYING`
/// file in the same directory as `go.mod`. Files are considered in deterministic
/// (sorted) order; the first that classifies wins. Returns `None` when none match.
fn module_license(ctx: &CatalogContext, gomod_path: &Path) -> Option<String> {
    let dir = gomod_path.parent();
    let mut candidates: Vec<&Path> = ctx
        .files
        .iter()
        .filter(|p| p.parent() == dir && is_license_filename(p))
        .map(|p| p.as_path())
        .collect();
    candidates.sort();
    for cand in candidates {
        if let Some(spdx) = read_bounded(cand)
            .ok()
            .and_then(|t| classify_license_text(&t))
        {
            return Some(spdx);
        }
    }
    None
}

/// True for a bare `LICENSE`/`COPYING` file (optionally with a `.txt`/`.md`
/// suffix or a `LICENSE-MIT`-style variant). Case-insensitive.
fn is_license_filename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let upper = name.to_ascii_uppercase();
    upper.starts_with("LICENSE") || upper.starts_with("LICENCE") || upper.starts_with("COPYING")
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

/// Read at most 256 KiB of a (license) file as lossy UTF-8 — bounded against
/// untrusted, possibly huge files. Larger files are truncated for classification.
fn read_bounded(path: &Path) -> Result<String, CatalogError> {
    let bytes = fs::read(path).map_err(|source| CatalogError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let slice = &bytes[..bytes.len().min(256 * 1024)];
    Ok(String::from_utf8_lossy(slice).into_owned())
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
    // go.mod
    // -----------------------------------------------------------------------

    #[test]
    fn gomod_yields_direct_and_indirect_requires() {
        let ctx = fixture_ctx("go");
        let out = GoCataloger.catalog(&ctx).unwrap();
        let names: Vec<_> = out
            .iter()
            .filter(|c| c.matching_method == "go_mod")
            .map(|c| c.name.as_str())
            .collect();
        assert!(
            names.contains(&"github.com/gorilla/mux"),
            "gorilla/mux must be present"
        );
        assert!(
            names.contains(&"golang.org/x/crypto"),
            "x/crypto must be present (indirect counts)"
        );
        assert!(
            names.contains(&"github.com/Azure/go-autorest"),
            "Azure/go-autorest must be present (case preserved)"
        );
    }

    #[test]
    fn gomod_does_not_emit_module_go_toolchain() {
        let ctx = fixture_ctx("go");
        let out = GoCataloger.catalog(&ctx).unwrap();
        // The `go` and `toolchain` lines must never appear; the `module` path must
        // not appear as a require/dependency (it is the project self-component).
        let bad: Vec<_> = out
            .iter()
            .filter(|c| {
                c.name == "1.21"
                    || c.name.contains("toolchain")
                    || (c.name == "github.com/example/myapp" && c.matching_method == "go_mod")
            })
            .collect();
        assert!(
            bad.is_empty(),
            "module/go/toolchain must not be dependency components: {bad:?}"
        );
        // The module is emitted exactly once, as the source self-component.
        let module_comps: Vec<_> = out
            .iter()
            .filter(|c| c.name == "github.com/example/myapp")
            .collect();
        assert_eq!(module_comps.len(), 1, "module emitted once as self");
        assert_eq!(module_comps[0].matching_method, "go_mod_project");
        assert_eq!(module_comps[0].component_type, "source");
    }

    #[test]
    fn gomod_version_keeps_leading_v() {
        let ctx = fixture_ctx("go");
        let out = GoCataloger.catalog(&ctx).unwrap();
        let mux = out
            .iter()
            .find(|c| c.name == "github.com/gorilla/mux")
            .unwrap();
        assert_eq!(mux.version.as_deref(), Some("v1.8.1"));
    }

    #[test]
    fn gomod_purl_preserves_case_and_slashes() {
        let ctx = fixture_ctx("go");
        let out = GoCataloger.catalog(&ctx).unwrap();
        let mux = out
            .iter()
            .find(|c| c.name == "github.com/gorilla/mux")
            .unwrap();
        assert_eq!(
            mux.purl.as_deref(),
            Some("pkg:golang/github.com/gorilla/mux@v1.8.1")
        );
        // Azure with capital A.
        let azure = out
            .iter()
            .find(|c| c.name == "github.com/Azure/go-autorest")
            .unwrap();
        assert_eq!(
            azure.purl.as_deref(),
            Some("pkg:golang/github.com/Azure/go-autorest@v14.2.0+incompatible")
        );
    }

    #[test]
    fn gomod_evidence_is_resolved() {
        let ctx = fixture_ctx("go");
        let out = GoCataloger.catalog(&ctx).unwrap();
        let mux = out
            .iter()
            .find(|c| c.name == "github.com/gorilla/mux")
            .unwrap();
        assert_eq!(top_rung(&mux.evidence), Some(EvidenceKind::Resolved));
    }

    // -----------------------------------------------------------------------
    // replace / exclude directives
    // -----------------------------------------------------------------------

    #[test]
    fn gomod_replace_redirects_to_new_module_version() {
        let ctx = fixture_ctx("go");
        let out = GoCataloger.catalog(&ctx).unwrap();
        // `replace github.com/old/redirected v1.0.0 => github.com/new/replacement v2.5.0`
        // The original require must NOT be emitted at its original version; the
        // replacement (new path + new version) is emitted instead.
        let original: Vec<_> = out
            .iter()
            .filter(|c| c.name == "github.com/old/redirected")
            .collect();
        assert!(
            original.is_empty(),
            "redirected module must not be emitted at its original coordinate: {original:?}"
        );
        let replacement = out
            .iter()
            .find(|c| c.name == "github.com/new/replacement")
            .expect("replacement module must be emitted");
        assert_eq!(replacement.version.as_deref(), Some("v2.5.0"));
        assert_eq!(
            replacement.purl.as_deref(),
            Some("pkg:golang/github.com/new/replacement@v2.5.0")
        );
    }

    #[test]
    fn gomod_local_path_replace_has_no_version() {
        let ctx = fixture_ctx("go");
        let out = GoCataloger.catalog(&ctx).unwrap();
        // `replace github.com/old/localized => ./vendor/localized` (factored block).
        // A local-path replace strips the version (source-only, no PyPI/registry pin).
        let localized = out
            .iter()
            .find(|c| c.name == "github.com/old/localized")
            .expect("local-path-replaced module must still be emitted");
        assert!(
            localized.version.is_none(),
            "local-path replace has no version: {:?}",
            localized.version
        );
        assert!(
            localized.purl.is_none(),
            "no version → no PURL: {:?}",
            localized.purl
        );
    }

    #[test]
    fn gomod_exclude_drops_path_version() {
        let ctx = fixture_ctx("go");
        let out = GoCataloger.catalog(&ctx).unwrap();
        // `exclude github.com/dropme/excluded v0.9.0` (factored block) must drop it.
        let excluded: Vec<_> = out
            .iter()
            .filter(|c| c.name == "github.com/dropme/excluded")
            .collect();
        assert!(
            excluded.is_empty(),
            "excluded (path,version) must be dropped: {excluded:?}"
        );
    }

    #[test]
    fn gomod_single_line_replace_and_exclude() {
        // A go.mod with single-line `replace`/`exclude` directives (not factored).
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("go.mod");
        std::fs::write(
            &p,
            "module example.com/m\n\
             go 1.21\n\
             require github.com/a/redirect v1.0.0\n\
             require github.com/a/keep v3.1.0\n\
             require github.com/a/gone v0.1.0\n\
             replace github.com/a/redirect v1.0.0 => github.com/b/dest v4.0.0\n\
             exclude github.com/a/gone v0.1.0\n",
        )
        .unwrap();
        let ctx = CatalogContext::new(dir.path().to_path_buf(), vec![p]);
        let out = GoCataloger.catalog(&ctx).unwrap();
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"github.com/b/dest"),
            "redirect target present"
        );
        assert!(!names.contains(&"github.com/a/redirect"), "original gone");
        assert!(
            names.contains(&"github.com/a/keep"),
            "unaffected require kept"
        );
        assert!(!names.contains(&"github.com/a/gone"), "excluded dropped");
        let dest = out.iter().find(|c| c.name == "github.com/b/dest").unwrap();
        assert_eq!(dest.version.as_deref(), Some("v4.0.0"));
    }

    // -----------------------------------------------------------------------
    // go.sum
    // -----------------------------------------------------------------------

    #[test]
    fn gosum_h1_recorded_as_evidence_not_as_hash_ref() {
        let ctx = fixture_ctx("go");
        let out = GoCataloger.catalog(&ctx).unwrap();
        let mux = out
            .iter()
            .find(|c| c.name == "github.com/gorilla/mux")
            .unwrap();
        // hashes[] must be empty — h1: is NOT a raw tarball SHA-256.
        assert!(
            mux.hashes.is_empty(),
            "go.sum h1: must not appear in hashes[]: {:?}",
            mux.hashes
        );
        // But an evidence note with the h1 locator must exist.
        let has_h1 = mux.evidence.iter().any(|e| {
            e.locator
                .as_deref()
                .map(|l| l.starts_with("h1:"))
                .unwrap_or(false)
        });
        assert!(has_h1, "h1: dirhash must appear as evidence locator");
    }

    #[test]
    fn gosum_gomod_only_lines_are_not_extra_components() {
        let ctx = fixture_ctx("go");
        let out = GoCataloger.catalog(&ctx).unwrap();
        // go.mod + go.sum combined; gorilla/mux appears once in go.mod and twice
        // in go.sum (`h1:` line + `/go.mod h1:` line) — should collapse to 1 component.
        let mux_comps: Vec<_> = out
            .iter()
            .filter(|c| c.name == "github.com/gorilla/mux")
            .collect();
        assert_eq!(mux_comps.len(), 1, "gorilla/mux must appear exactly once");
    }

    // -----------------------------------------------------------------------
    // Detect
    // -----------------------------------------------------------------------

    #[test]
    fn detect_true_for_go_mod() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/go.mod".into()]);
        assert!(GoCataloger.detect(&ctx));
    }

    #[test]
    fn detect_false_without_go_mod() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/go.sum".into()]);
        assert!(!GoCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // merge_by_identity: go.mod + go.sum collapse
    // -----------------------------------------------------------------------

    #[test]
    fn gomod_and_gosum_merge_into_one_component() {
        let ctx = fixture_ctx("go");
        let raw = GoCataloger.catalog(&ctx).unwrap();
        let merged = crate::merge_by_identity(raw);
        // gorilla/mux from go.mod + go.sum evidence → exactly 1 merged component.
        let mux: Vec<_> = merged
            .iter()
            .filter(|c| c.purl.as_deref() == Some("pkg:golang/github.com/gorilla/mux@v1.8.1"))
            .collect();
        assert_eq!(
            mux.len(),
            1,
            "gorilla/mux must merge to exactly 1 component"
        );
    }

    // -----------------------------------------------------------------------
    // module self-component + LICENSE classification (item 9)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_module_directive_handles_plain_and_quoted() {
        assert_eq!(
            parse_module_directive("module github.com/a/b\ngo 1.21\n").as_deref(),
            Some("github.com/a/b")
        );
        assert_eq!(
            parse_module_directive("module \"github.com/a/b\"\n").as_deref(),
            Some("github.com/a/b")
        );
        assert!(parse_module_directive("go 1.21\n").is_none());
    }

    #[test]
    fn classify_license_text_detects_common_licenses() {
        assert_eq!(
            classify_license_text("Permission is hereby granted, free of charge, to any person")
                .as_deref(),
            Some("MIT")
        );
        assert_eq!(
            classify_license_text("Apache License\nVersion 2.0, January 2004").as_deref(),
            Some("Apache-2.0")
        );
        assert_eq!(
            classify_license_text(
                "Redistribution and use in source and binary forms ... Neither the name of"
            )
            .as_deref(),
            Some("BSD-3-Clause")
        );
        assert!(classify_license_text("some random readme text").is_none());
    }

    #[test]
    fn gomod_self_component_with_license() {
        let dir = tempfile::TempDir::new().unwrap();
        let gomod = dir.path().join("go.mod");
        let license = dir.path().join("LICENSE");
        std::fs::write(
            &gomod,
            "module github.com/example/myapp\n\ngo 1.21\n\nrequire github.com/gorilla/mux v1.8.1\n",
        )
        .unwrap();
        std::fs::write(
            &license,
            "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\n",
        )
        .unwrap();
        let ctx = CatalogContext::new(dir.path().to_path_buf(), vec![gomod, license]);
        let out = GoCataloger.catalog(&ctx).unwrap();
        let self_comp = out
            .iter()
            .find(|c| c.matching_method == "go_mod_project")
            .expect("module self-component must be emitted");
        assert_eq!(self_comp.name, "github.com/example/myapp");
        assert_eq!(self_comp.component_type, "source");
        assert!(self_comp.version.is_none(), "go.mod has no module version");
        assert_eq!(
            self_comp.purl.as_deref(),
            Some("pkg:golang/github.com/example/myapp")
        );
        assert_eq!(self_comp.license.as_deref(), Some("MIT"));
        assert_eq!(self_comp.evidence_summary(), "go.mod");
    }
}
