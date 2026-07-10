// SPDX-License-Identifier: Apache-2.0

//! The SBOM component model. Mirrors the legacy `governance::Component` so the
//! migration is behavior-preserving, but carries a structured evidence ladder.

use crate::evidence::{top_rung, usage_label, Evidence};

/// One content hash of a component's artifact. CycloneDX wants hex; native
/// formats vary (SRI base64, contentHash base64, go.sum dirhash) — the cataloger
/// decodes to hex and records the algorithm so it is never mislabeled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashRef {
    pub alg: String, // CycloneDX alg id, e.g. "SHA-256", "SHA-512", "SHA-1"
    pub value_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub component_ref: String,
    pub name: String,
    /// Namespace/group for ecosystems that carry one (Maven `groupId`, the only
    /// current producer). `None` for flat-namespace ecosystems (cargo, npm, …).
    /// Rendered as the CycloneDX `group` field and folded into the `bom-ref`.
    pub group: Option<String>,
    pub version: Option<String>,
    pub ecosystem: String,
    pub component_type: String,
    pub supplier: Option<String>,
    pub license: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub sha256: Option<String>,
    pub hashes: Vec<HashRef>,
    pub identity_confidence: String,
    pub matching_method: String,
    pub evidence: Vec<Evidence>,
    pub runtime_harnesses: Vec<String>,
}

/// Identity used to collapse the same library seen from different sources.
/// Priority: purl → (ecosystem, name, version) → (name, sha256) → name.
/// Phase 1 does not merge on this key (legacy dedup is preserved); Phase 2 will.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ComponentKey {
    Purl(String),
    NameVersion(String, String, Option<String>),
    NameSha(String, String),
    Fallback(String),
}

impl Component {
    /// The legacy `evidence` JSON value: the evidence sources joined by `;`.
    /// For a single-evidence component this equals the original string exactly.
    pub fn evidence_summary(&self) -> String {
        self.evidence
            .iter()
            .map(|item| item.source.clone())
            .collect::<Vec<_>>()
            .join(";")
    }

    /// Coarse usage label from the top evidence rung (for later phases).
    pub fn usage(&self) -> &'static str {
        usage_label(top_rung(&self.evidence))
    }

    pub fn identity_key(&self) -> ComponentKey {
        if let Some(purl) = &self.purl {
            return ComponentKey::Purl(purl.clone());
        }
        if self.version.is_some() {
            return ComponentKey::NameVersion(
                self.ecosystem.clone(),
                self.name.clone(),
                self.version.clone(),
            );
        }
        if let Some(sha) = &self.sha256 {
            return ComponentKey::NameSha(self.name.clone(), sha.clone());
        }
        ComponentKey::Fallback(format!("{}/{}", self.ecosystem, self.name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::EvidenceKind;

    fn sample(evidence: Vec<Evidence>) -> Component {
        Component {
            component_ref: String::new(),
            name: "zlib".to_owned(),
            version: Some("1.3.1".to_owned()),
            ecosystem: "cargo".to_owned(),
            group: None,
            component_type: "source".to_owned(),
            supplier: None,
            license: None,
            purl: Some("pkg:cargo/zlib@1.3.1".to_owned()),
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "high".to_owned(),
            matching_method: "cargo_manifest".to_owned(),
            evidence,
            runtime_harnesses: Vec::new(),
        }
    }

    #[test]
    fn evidence_summary_of_single_entry_is_the_source() {
        let c = sample(vec![Evidence::new(EvidenceKind::Declared, "Cargo.toml")]);
        assert_eq!(c.evidence_summary(), "Cargo.toml");
    }

    #[test]
    fn evidence_summary_joins_multiple_sources() {
        let c = sample(vec![
            Evidence::new(EvidenceKind::Declared, "Cargo.toml"),
            Evidence::new(EvidenceKind::SourceObserved, "src/lib.rs:3"),
        ]);
        assert_eq!(c.evidence_summary(), "Cargo.toml;src/lib.rs:3");
    }

    #[test]
    fn identity_prefers_purl() {
        let c = sample(vec![]);
        assert_eq!(
            c.identity_key(),
            ComponentKey::Purl("pkg:cargo/zlib@1.3.1".to_owned())
        );
    }

    #[test]
    fn identity_falls_back_through_namever_sha_and_name() {
        let mut c = sample(vec![]);
        c.purl = None;
        assert_eq!(
            c.identity_key(),
            ComponentKey::NameVersion(
                "cargo".to_owned(),
                "zlib".to_owned(),
                Some("1.3.1".to_owned())
            )
        );

        c.version = None;
        c.sha256 = Some("abc123".to_owned());
        assert_eq!(
            c.identity_key(),
            ComponentKey::NameSha("zlib".to_owned(), "abc123".to_owned())
        );

        c.sha256 = None;
        assert_eq!(
            c.identity_key(),
            ComponentKey::Fallback("cargo/zlib".to_owned())
        );
    }

    #[test]
    fn hashes_carry_algorithm_and_hex() {
        let mut c = sample(vec![]);
        c.hashes = vec![
            HashRef {
                alg: "SHA-256".into(),
                value_hex: "abcd".into(),
            },
            HashRef {
                alg: "SHA-512".into(),
                value_hex: " effff".trim().into(),
            },
        ];
        assert_eq!(c.hashes[0].alg, "SHA-256");
        assert_eq!(c.hashes.len(), 2);
    }

    #[test]
    fn usage_reflects_top_rung() {
        let exercised = sample(vec![
            Evidence::new(EvidenceKind::Declared, "Cargo.toml"),
            Evidence::new(EvidenceKind::FuzzReached, "harness:zip_open"),
        ]);
        assert_eq!(exercised.usage(), "exercised");
        assert_eq!(sample(vec![]).usage(), "unknown");
    }
}
