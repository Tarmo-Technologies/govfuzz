// SPDX-License-Identifier: Apache-2.0

//! The cataloger abstraction. A cataloger inspects a tree and emits components
//! with evidence. Pure, offline, deterministic. Phase 2+ extends `CatalogContext`
//! with parsed ASTs, run.json, and binary inventories (additive fields).

use crate::component::Component;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("malformed {kind} manifest at {path}: {detail}")]
    Malformed {
        kind: String,
        path: PathBuf,
        detail: String,
    },
}

/// Read-only context handed to every cataloger. Treated as untrusted input.
#[derive(Debug, Clone)]
pub struct CatalogContext {
    pub root: PathBuf,
    /// All regular files under `root`, relative paths preserved by the walker.
    pub files: Vec<PathBuf>,
}

impl CatalogContext {
    pub fn new(root: PathBuf, files: Vec<PathBuf>) -> Self {
        CatalogContext { root, files }
    }

    /// Files whose final path component equals `name`.
    pub fn files_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a PathBuf> + 'a {
        self.files
            .iter()
            .filter(move |path| path.file_name().and_then(|n| n.to_str()) == Some(name))
    }

    /// Files whose final path component ends with `suffix` (e.g. `".gemspec"`).
    pub fn files_ending_with<'a>(
        &'a self,
        suffix: &'a str,
    ) -> impl Iterator<Item = &'a PathBuf> + 'a {
        self.files.iter().filter(move |path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(suffix))
                .unwrap_or(false)
        })
    }
}

pub trait Cataloger {
    /// Ecosystem label this cataloger emits (e.g. "cargo", "pypi").
    fn ecosystem(&self) -> &str;
    /// Cheap check: should this cataloger run against the tree at all?
    fn detect(&self, ctx: &CatalogContext) -> bool;
    /// Produce components with evidence. Must not touch the network.
    fn catalog(&self, ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Evidence, EvidenceKind};

    struct StubCataloger;
    impl Cataloger for StubCataloger {
        fn ecosystem(&self) -> &str {
            "stub"
        }
        fn detect(&self, ctx: &CatalogContext) -> bool {
            ctx.files_named("STUB").next().is_some()
        }
        fn catalog(&self, _ctx: &CatalogContext) -> Result<Vec<Component>, CatalogError> {
            Ok(vec![Component {
                component_ref: String::new(),
                name: "stub".to_owned(),
                version: None,
                ecosystem: "stub".to_owned(),
                group: None,
                component_type: "source".to_owned(),
                supplier: None,
                license: None,
                purl: None,
                cpe: None,
                sha256: None,
                hashes: Vec::new(),
                identity_confidence: "low".to_owned(),
                matching_method: "stub".to_owned(),
                evidence: vec![Evidence::new(EvidenceKind::Declared, "STUB")],
                runtime_harnesses: Vec::new(),
            }])
        }
    }

    #[test]
    fn detect_gates_on_marker_file() {
        let with = CatalogContext::new("/r".into(), vec!["/r/STUB".into()]);
        let without = CatalogContext::new("/r".into(), vec!["/r/README".into()]);
        assert!(StubCataloger.detect(&with));
        assert!(!StubCataloger.detect(&without));
    }

    #[test]
    fn catalog_emits_evidence() {
        let ctx = CatalogContext::new("/r".into(), vec!["/r/STUB".into()]);
        let out = StubCataloger.catalog(&ctx).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].evidence[0].kind, EvidenceKind::Declared);
    }
}
