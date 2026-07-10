// SPDX-License-Identifier: Apache-2.0

//! Tier-A Ada deep-extraction cataloger (`SourceObserved`).
//!
//! Scans `.ads`/`.adb` files for `with <Unit>;` context clauses and emits each
//! distinct third-party top-level unit root once as a `SourceObserved`
//! component (`ecosystem = "ada"`). Standard-library roots — `Ada.`, `System.`,
//! `Interfaces.`, `GNAT.`, and bare `Standard` — are skipped. A `with` clause
//! carries no version, so components are emitted with a `pkg:generic/<root>`
//! PURL and no `@version`.
//!
//! # Untrusted input
//! Files are size-bounded (≤4 MiB). Scanning is line-oriented and bounded:
//! `--` line comments are stripped, `with` is matched case-insensitively as a
//! whole word, and malformed clauses are tolerated. Never panics, never
//! networks.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::Component;
use crate::evidence::{Evidence, EvidenceKind};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Ada spec/body file extensions.
const ADA_EXTENSIONS: &[&str] = &["ads", "adb"];

/// Standard-library / runtime unit roots that are NOT third-party deps.
/// Compared case-insensitively against the first dotted segment.
const STDLIB_ROOTS: &[&str] = &["ada", "system", "interfaces", "gnat", "standard"];

pub struct AdaSourceCataloger;

impl Cataloger for AdaSourceCataloger {
    fn ecosystem(&self) -> &str {
        "ada"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files.iter().any(|p| is_ada_source(p))
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        // root (lowercased) → (canonical-cased root, evidence locators).
        let mut acc: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();

        // Unit roots DEFINED in the scanned tree — the project's OWN packages (and
        // any vendored library sources). GNAT file naming maps `My_App.Foo` to
        // `my_app-foo.ads`, so the root is the first `-`-segment of each Ada file
        // stem, lowercased. A `with` of an own package must NOT become an SBOM
        // component — only third-party units the tree references but never defines.
        let own_roots: std::collections::HashSet<String> = ctx
            .files
            .iter()
            .filter(|p| is_ada_source(p))
            .filter_map(|p| p.file_stem().and_then(|s| s.to_str()))
            .map(|stem| stem.split('-').next().unwrap_or(stem).to_ascii_lowercase())
            .collect();

        for path in ctx.files.iter().filter(|p| is_ada_source(p)) {
            let rel = relative_path(&ctx.root, path);
            let source = read_bounded(path)?;
            for (line_no, unit) in scan_withs(&source) {
                let root = unit_root(&unit);
                if root.is_empty()
                    || is_stdlib_root(&root)
                    || own_roots.contains(&root.to_ascii_lowercase())
                {
                    continue;
                }
                let key = root.to_ascii_lowercase();
                let locator = format!("{rel}:{line_no} with {unit};");
                let entry = acc.entry(key).or_insert_with(|| (root.clone(), Vec::new()));
                if !entry.1.contains(&locator) {
                    entry.1.push(locator);
                }
            }
        }

        let mut out = Vec::with_capacity(acc.len());
        for (_key, (root, locators)) in acc {
            out.push(make_component(&root, &locators));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// `with` clause scanning
// ---------------------------------------------------------------------------

/// Scan Ada source for `with <Unit>;` clauses. Case-insensitive `with` matched
/// as a whole word at a statement start; the unit is the dotted name up to the
/// first `;`. A single `with A, B;` (comma list) yields each unit. Returns
/// `(1-based line number, dotted unit name)`. Bounded; never panics.
fn scan_withs(source: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, raw_line) in source.lines().enumerate() {
        let line_no = i + 1;
        let line = strip_line_comment(raw_line);
        let trimmed = line.trim_start();
        // Match a leading `with` keyword (case-insensitive) followed by space.
        let Some(rest) = strip_keyword_ci(trimmed, "with") else {
            continue;
        };
        // Exclude `with private`, `for ... use ...`, and the `... with` aspect
        // form: we only accept a context clause that starts the (trimmed) line.
        let rest = rest.trim_start();
        // The clause body runs up to the first ';' (Ada statement terminator).
        let body = match rest.find(';') {
            Some(idx) => &rest[..idx],
            None => rest, // tolerate a missing terminator
        };
        for unit in body.split(',') {
            let unit = sanitize_unit(unit);
            if !unit.is_empty() {
                out.push((line_no, unit));
            }
        }
    }
    out
}

/// Strip a trailing `--` Ada line comment.
fn strip_line_comment(line: &str) -> &str {
    match line.find("--") {
        Some(idx) => &line[..idx],
        None => line,
    }
}

/// If `s` begins with the keyword `kw` (ASCII case-insensitive) as a whole word
/// (followed by whitespace or end), return the remainder after it.
fn strip_keyword_ci<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
    // `get(..kw.len())` is None when `s` is shorter than `kw` OR when `kw.len()`
    // lands inside a multi-byte char — e.g. a line beginning `" µs=" & …` where
    // a 3-byte char sits in the first 4 bytes. A blind `split_at(kw.len())` there
    // panics ("byte index N is not a char boundary"). `kw` is always ASCII, so a
    // successful `get` also proves `kw.len()` is a valid boundary for the tail.
    let head = s.get(..kw.len())?;
    if !head.eq_ignore_ascii_case(kw) {
        return None;
    }
    let tail = &s[kw.len()..];
    // Must be a word boundary: next char is whitespace (or nothing).
    match tail.chars().next() {
        None => Some(tail),
        Some(c) if c.is_whitespace() => Some(tail),
        _ => None,
    }
}

/// Keep only a valid dotted Ada unit name: letters, digits, `_`, `.`. Stops at
/// the first other character (e.g. a trailing keyword or paren). Trims dots.
fn sanitize_unit(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.trim().chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            break;
        }
    }
    out.trim_matches('.').to_owned()
}

/// First dotted segment of a unit name (`Gnatcoll.Json` → `Gnatcoll`).
fn unit_root(unit: &str) -> String {
    unit.split('.').next().unwrap_or(unit).to_owned()
}

fn is_stdlib_root(root: &str) -> bool {
    let lc = root.to_ascii_lowercase();
    STDLIB_ROOTS.contains(&lc.as_str())
}

// ---------------------------------------------------------------------------
// Component construction
// ---------------------------------------------------------------------------

fn make_component(root: &str, locators: &[String]) -> Component {
    let evidence = locators
        .iter()
        .map(|loc| Evidence::new(EvidenceKind::SourceObserved, loc.clone()))
        .collect();
    Component {
        component_ref: String::new(),
        name: root.to_owned(),
        version: None, // a `with` alone carries no version
        ecosystem: "ada".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        // No version → bare pkg:generic name (no `@version`).
        purl: Some(format!("pkg:generic/{}", root.to_ascii_lowercase())),
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "low".to_owned(),
        matching_method: "ada_source_with".to_owned(),
        evidence,
        runtime_harnesses: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_ada_source(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| ADA_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
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
    // scan_withs unit behavior
    // -----------------------------------------------------------------------

    #[test]
    fn scan_extracts_dotted_unit() {
        let withs = scan_withs("with Gnatcoll.Json;\n");
        assert_eq!(withs.len(), 1);
        assert_eq!(withs[0].1, "Gnatcoll.Json");
    }

    #[test]
    fn scan_is_case_insensitive_on_keyword() {
        let withs = scan_withs("WITH Mylib.Core;\nWith Other.Unit;\n");
        let units: Vec<_> = withs.iter().map(|w| w.1.as_str()).collect();
        assert!(units.contains(&"Mylib.Core"));
        assert!(units.contains(&"Other.Unit"));
    }

    #[test]
    fn scan_handles_comma_list() {
        let withs = scan_withs("with A.B, C.D, E;\n");
        let units: Vec<_> = withs.iter().map(|w| w.1.as_str()).collect();
        assert_eq!(units, vec!["A.B", "C.D", "E"]);
    }

    #[test]
    fn scan_strips_line_comment() {
        let withs = scan_withs("with Real.Unit; -- with Fake.Unit;\n");
        let units: Vec<_> = withs.iter().map(|w| w.1.as_str()).collect();
        assert_eq!(units, vec!["Real.Unit"]);
    }

    #[test]
    fn scan_ignores_withhold_like_identifiers() {
        // `withhold` must not be treated as a `with` keyword (word boundary).
        let withs = scan_withs("withhold := 1;\n");
        assert!(withs.is_empty());
    }

    #[test]
    fn scan_does_not_panic_on_malformed() {
        for s in ["with", "with ;", "with .;", "with (\n", "with Foo"] {
            let _ = scan_withs(s);
        }
    }

    // -----------------------------------------------------------------------
    // detect
    // -----------------------------------------------------------------------

    #[test]
    fn catalog_lists_external_withs_but_excludes_own_and_stdlib() {
        // The tree defines `My_App` + `My_App.Utils` (own). Its body withs a
        // stdlib unit, a runtime unit, an own child, and two third-party libs. Only
        // the third-party libs (AWS, GNATCOLL) belong in the SBOM.
        let (_dir, ctx) = temp_ctx(&[
            ("my_app.ads", "package My_App is\nend My_App;\n"),
            (
                "my_app-utils.ads",
                "package My_App.Utils is\nend My_App.Utils;\n",
            ),
            (
                "my_app.adb",
                "with Ada.Text_IO;\nwith GNAT.OS_Lib;\nwith My_App.Utils;\n\
                 with AWS.Server;\nwith GNATCOLL.JSON;\npackage body My_App is\nend My_App;\n",
            ),
        ]);
        let mut names: Vec<String> = AdaSourceCataloger
            .catalog(&ctx)
            .unwrap()
            .into_iter()
            .map(|c| c.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["AWS".to_owned(), "GNATCOLL".to_owned()]);
    }

    #[test]
    fn detect_true_for_ada_files() {
        let ads = CatalogContext::new("/r".into(), vec!["/r/pkg.ads".into()]);
        assert!(AdaSourceCataloger.detect(&ads));
        let adb = CatalogContext::new("/r".into(), vec!["/r/pkg.adb".into()]);
        assert!(AdaSourceCataloger.detect(&adb));
    }

    #[test]
    fn detect_false_without_ada_files() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/main.c".into()]);
        assert!(!AdaSourceCataloger.detect(&ctx));
    }

    // -----------------------------------------------------------------------
    // End-to-end against the ada_source fixture
    // -----------------------------------------------------------------------

    #[test]
    fn third_party_units_emitted_stdlib_skipped() {
        let ctx = fixture_ctx("ada_source");
        let out = AdaSourceCataloger.catalog(&ctx).unwrap();
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"Gnatcoll"),
            "Gnatcoll must appear: {names:?}"
        );
        assert!(names.contains(&"Mylib"), "Mylib must appear: {names:?}");
        // stdlib roots skipped.
        assert!(!names.contains(&"Ada"), "Ada.* must be skipped");
        assert!(
            !names.contains(&"Interfaces"),
            "Interfaces.* must be skipped"
        );
        assert!(!names.contains(&"System"), "System.* must be skipped");
        assert!(!names.contains(&"GNAT"), "GNAT.* must be skipped");
    }

    #[test]
    fn emitted_units_are_source_observed_generic_purl_no_version() {
        let ctx = fixture_ctx("ada_source");
        let out = AdaSourceCataloger.catalog(&ctx).unwrap();
        let gnatcoll = out
            .iter()
            .find(|c| c.name == "Gnatcoll")
            .expect("Gnatcoll present");
        assert_eq!(gnatcoll.ecosystem, "ada");
        assert!(gnatcoll.version.is_none(), "with carries no version");
        assert_eq!(gnatcoll.purl.as_deref(), Some("pkg:generic/gnatcoll"));
        assert_eq!(
            top_rung(&gnatcoll.evidence),
            Some(EvidenceKind::SourceObserved)
        );
        assert!(gnatcoll.evidence[0].source.contains("with Gnatcoll.Json;"));
    }

    #[test]
    fn root_dedups_across_subunits_and_files() {
        let (_d, ctx) = temp_ctx(&[
            ("a.adb", "with Gnatcoll.Json;\nwith Gnatcoll.Strings;\n"),
            ("b.adb", "with Gnatcoll.Email;\n"),
        ]);
        let out = AdaSourceCataloger.catalog(&ctx).unwrap();
        let gnatcoll: Vec<_> = out.iter().filter(|c| c.name == "Gnatcoll").collect();
        assert_eq!(gnatcoll.len(), 1, "one component for the root");
        // Three distinct with-sites union into the evidence.
        assert_eq!(gnatcoll[0].evidence.len(), 3);
    }

    #[test]
    fn non_ascii_line_prefix_does_not_panic() {
        // Regression: a source line whose trimmed prefix begins with a multi-byte
        // char — e.g. an Ada constant/argument continuation like
        // `" µs=" & Ss_Tim_Types.Microsecond_Type'Image` — fed the `with`-scanner
        // a `split_at("with".len())` (== 4) that landed INSIDE the 3-byte char,
        // panicking with "byte index 4 is not a char boundary" during the campaign
        // SBOM (emit_campaign_sbom -> AdaSourceCataloger::catalog). It must not
        // panic, and the real `with` clauses must still be extracted.
        let (_d, ctx) = temp_ctx(&[(
            "telemetry.adb",
            "with Gnatcoll.Json;\n\
             package body Telemetry is\n\
             \x20\x20 Msg : constant String :=\n\
             \x20\x20\x20\x20 \" \u{20ac}s=\" & Ss_Tim_Types.Microsecond_Type'Image;\n\
             end Telemetry;\n",
        )]);
        let out = AdaSourceCataloger
            .catalog(&ctx)
            .expect("cataloger must not panic on a non-ASCII line prefix");
        let names: Vec<_> = out.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"Gnatcoll"),
            "the real `with Gnatcoll.Json;` must still be found: {names:?}"
        );
    }
}
