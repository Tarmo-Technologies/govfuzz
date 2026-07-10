// SPDX-License-Identifier: Apache-2.0

//! Perl (CPAN) ecosystem cataloger.
//!
//! **Declared**: `cpanfile` (`requires 'Module', 'version';` and the
//! `recommends`/`*_requires` variants, including inside `on '...' => sub { ... }`
//! phase blocks) and `Makefile.PL` (`PREREQ_PM => { 'Module' => 'ver', ... }`).
//! **Resolved-ish**: `META.json` / `MYMETA.json` (CPAN::Meta spec — the `prereqs`
//! tree of phase → relationship → `{ Module: version }`).
//!
//! PURL: `pkg:cpan/<Module>@<version>` (version omitted for a range constraint).
//! Module names are case-sensitive (`JSON::PP`) — never lowercased.

use crate::cataloger::{CatalogContext, CatalogError, Cataloger};
use crate::component::Component;
use crate::evidence::{Evidence, EvidenceKind};
use crate::purl;
use std::fs;
use std::path::Path;

pub struct PerlCataloger;

impl Cataloger for PerlCataloger {
    fn ecosystem(&self) -> &str {
        "cpan"
    }

    fn detect(&self, ctx: &CatalogContext) -> bool {
        ctx.files_named("cpanfile").next().is_some()
            || ctx.files_named("META.json").next().is_some()
            || ctx.files_named("MYMETA.json").next().is_some()
            || ctx.files_named("Makefile.PL").next().is_some()
    }

    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
        let mut out = Vec::new();
        for name in ["META.json", "MYMETA.json"] {
            for path in ctx.files_named(name) {
                let rel = relative_path(&ctx.root, path);
                for (module, version) in parse_meta_json(path) {
                    out.push(component(
                        module,
                        version,
                        &rel,
                        EvidenceKind::Resolved,
                        "meta_json",
                    ));
                }
            }
        }
        for path in ctx.files_named("cpanfile") {
            let rel = relative_path(&ctx.root, path);
            for (module, version) in parse_cpanfile(path) {
                out.push(component(
                    module,
                    version,
                    &rel,
                    EvidenceKind::Declared,
                    "cpanfile",
                ));
            }
        }
        for path in ctx.files_named("Makefile.PL") {
            let rel = relative_path(&ctx.root, path);
            for (module, version) in parse_makefile_pl(path) {
                out.push(component(
                    module,
                    version,
                    &rel,
                    EvidenceKind::Declared,
                    "makefile_pl",
                ));
            }
        }
        Ok(out)
    }
}

/// A pinned version is a single concrete value (`2.0`, `v1.2.3`, `1.203`), not a
/// range/constraint (`>= 2`, `0` placeholder). Returns the cleaned version or None.
fn clean_version(raw: &str) -> Option<String> {
    let v = raw.trim().trim_start_matches('v').trim();
    if v.is_empty() || v == "0" {
        return None;
    }
    // Reject range operators / spaces (constraints, not pins).
    if v.bytes()
        .all(|b| b.is_ascii_digit() || b == b'.' || b == b'_')
    {
        Some(v.to_owned())
    } else {
        None
    }
}

fn component(
    module: String,
    version: Option<String>,
    rel: &str,
    kind: EvidenceKind,
    method: &str,
) -> Component {
    let purl_val = match &version {
        Some(v) => purl::cpan(&module, v),
        None => purl::cpan_nameonly(&module),
    };
    let source = format!("{rel}:{module}");
    Component {
        component_ref: String::new(),
        name: module,
        version,
        ecosystem: "cpan".to_owned(),
        group: None,
        component_type: "library".to_owned(),
        supplier: None,
        license: None,
        purl: Some(purl_val),
        cpe: None,
        sha256: None,
        hashes: Vec::new(),
        identity_confidence: "medium".to_owned(),
        matching_method: method.to_owned(),
        evidence: vec![Evidence::new(kind, source)],
        runtime_harnesses: Vec::new(),
    }
}

/// Parse `requires`/`recommends`/`*_requires` lines from a cpanfile. `perl` itself
/// is a version dependency, not a CPAN module — skipped.
fn parse_cpanfile(path: &Path) -> Vec<(String, Option<String>)> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let line = line
            .strip_prefix("requires")
            .map(|r| (r, true))
            .or_else(|| {
                [
                    "recommends",
                    "suggests",
                    "test_requires",
                    "build_requires",
                    "configure_requires",
                ]
                .iter()
                .find_map(|kw| line.strip_prefix(kw).map(|r| (r, true)))
            });
        let Some((rest, _)) = line else { continue };
        // rest looks like: ` 'Module::Name', '0.10';` or ` "Module";` — drop the
        // statement terminator and any trailing block syntax first.
        let rest = rest.trim().trim_end_matches(';').trim();
        let mut parts = rest.splitn(2, ',');
        let Some(name_tok) = parts.next() else {
            continue;
        };
        let name = name_tok
            .trim()
            .trim_matches(|c| c == '\'' || c == '"' || c == ' ');
        if name.is_empty() || name == "perl" || !is_module_name(name) {
            continue;
        }
        let version = parts
            .next()
            .map(|v| v.trim().trim_matches(|c| c == '\'' || c == '"' || c == ' '))
            .and_then(clean_version);
        out.push((name.to_owned(), version));
    }
    out
}

/// Parse the CPAN::Meta `prereqs` tree from META.json/MYMETA.json.
fn parse_meta_json(path: &Path) -> Vec<(String, Option<String>)> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(prereqs) = json.get("prereqs").and_then(|p| p.as_object()) {
        for (_phase, rels) in prereqs {
            let Some(rels) = rels.as_object() else {
                continue;
            };
            for (_rel, modules) in rels {
                let Some(modules) = modules.as_object() else {
                    continue;
                };
                for (module, ver) in modules {
                    if module == "perl" || !is_module_name(module) {
                        continue;
                    }
                    let version = ver
                        .as_str()
                        .map(str::to_owned)
                        .and_then(|v| clean_version(&v));
                    out.push((module.clone(), version));
                }
            }
        }
    }
    out
}

/// Parse `PREREQ_PM`/`*_REQUIRES` hashes from Makefile.PL (regex over the literal
/// hash — never eval the Perl).
fn parse_makefile_pl(path: &Path) -> Vec<(String, Option<String>)> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // Find a `PREREQ_PM => { ... }` (or BUILD_REQUIRES/TEST_REQUIRES/...) block and
    // extract `'Module' => 'ver'` pairs from it.
    for key in [
        "PREREQ_PM",
        "BUILD_REQUIRES",
        "TEST_REQUIRES",
        "CONFIGURE_REQUIRES",
    ] {
        let Some(start) = text.find(key) else {
            continue;
        };
        let after = &text[start..];
        let Some(open) = after.find('{') else {
            continue;
        };
        let Some(close_rel) = after[open..].find('}') else {
            continue;
        };
        let block = &after[open + 1..open + close_rel];
        for pair in block.split(',') {
            let mut kv = pair.splitn(2, "=>");
            let Some(k) = kv.next() else { continue };
            let name = k.trim().trim_matches(|c| c == '\'' || c == '"' || c == ' ');
            if name.is_empty() || name == "perl" || !is_module_name(name) {
                continue;
            }
            let version = kv
                .next()
                .map(|v| v.trim().trim_matches(|c| c == '\'' || c == '"' || c == ' '))
                .and_then(clean_version);
            out.push((name.to_owned(), version));
        }
    }
    out
}

/// A plausible Perl module name: identifier chars + `::`, starting with a letter.
fn is_module_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn parses_cpanfile_requires() {
        let dir = std::env::temp_dir().join(format!("gf_cpan_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let p = write(
            &dir,
            "cpanfile",
            "requires 'JSON::PP', '2.0';\nrequires \"Moose\";\nrequires 'perl', '5.010';\non 'test' => sub {\n  requires 'Test::More', '0.88';\n};\n",
        );
        let deps = parse_cpanfile(&p);
        let names: Vec<&str> = deps.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"JSON::PP"));
        assert!(names.contains(&"Moose"));
        assert!(names.contains(&"Test::More"), "phase-block requires parsed");
        assert!(!names.contains(&"perl"), "perl itself skipped");
        let jp = deps.iter().find(|(n, _)| n == "JSON::PP").unwrap();
        assert_eq!(jp.1.as_deref(), Some("2.0"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_meta_json_prereqs() {
        let dir = std::env::temp_dir().join(format!("gf_cpanmeta_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let p = write(
            &dir,
            "META.json",
            r#"{"prereqs":{"runtime":{"requires":{"JSON::PP":"2.0","perl":"5.010"}},"test":{"requires":{"Test::More":"0.88"}}}}"#,
        );
        let deps = parse_meta_json(&p);
        let names: Vec<&str> = deps.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"JSON::PP"));
        assert!(names.contains(&"Test::More"));
        assert!(!names.contains(&"perl"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cpan_purl_form() {
        let c = component(
            "JSON::PP".to_owned(),
            Some("2.0".to_owned()),
            "cpanfile",
            EvidenceKind::Declared,
            "cpanfile",
        );
        assert_eq!(c.ecosystem, "cpan");
        assert_eq!(c.purl.as_deref(), Some("pkg:cpan/JSON::PP@2.0"));
    }
}
