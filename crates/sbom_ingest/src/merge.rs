// SPDX-License-Identifier: Apache-2.0

//! Identity-key merge that accumulates evidence across manifest + lockfile
//! sources. Replaces Phase-1 sort+dedup with a proper BTreeMap grouping that
//! unions evidence rungs and prefers Resolved-lane fields over Declared.

use crate::component::{Component, ComponentKey};
use crate::evidence::top_rung;

/// Collapse components sharing a `ComponentKey` into one, unioning evidence and
/// preferring Resolved-lane fields (exact version, hash, license) over Declared.
/// Deterministic output: sorted by (ecosystem, name, version, purl).
///
/// # Post-pass: versionless → versioned collapse
/// After primary keying, any group whose representative has `version = None`
/// (a range dep or otherwise unresolved entry) is folded into the sole versioned
/// group for the same `(ecosystem, name)` if **exactly one** such group exists.
/// When zero or two-or-more versioned groups exist the versionless entry is left
/// as-is — we never guess which version to attach it to.
pub fn merge_by_identity(components: Vec<Component>) -> Vec<Component> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<String, Component> = BTreeMap::new();
    for incoming in components {
        let key = key_string(&incoming.identity_key());
        match groups.get_mut(&key) {
            Some(existing) => merge_into(existing, incoming),
            None => {
                groups.insert(key, incoming);
            }
        }
    }

    // Post-pass: collapse versionless groups into the sole versioned group for
    // the same (ecosystem, name), when unambiguous.
    let mut versioned: BTreeMap<String, Component> = BTreeMap::new();
    let mut versionless: Vec<(String, Component)> = Vec::new();
    for (key, comp) in groups {
        if comp.version.is_none() {
            versionless.push((key, comp));
        } else {
            versioned.insert(key, comp);
        }
    }
    for (vl_key, vl_comp) in versionless {
        // Collect keys of versioned groups this versionless entry folds into.
        let matches: Vec<String> = versioned
            .iter()
            .filter(|(_, c)| same_versionless_target(&vl_comp, c))
            .map(|(k, _)| k.clone())
            .collect();
        if matches.len() == 1 {
            // Exactly one: safe to merge evidence into it.
            let target = versioned.get_mut(&matches[0]).unwrap();
            merge_into(target, vl_comp);
        } else {
            // Zero or ambiguous (2+): keep the versionless entry separate.
            versioned.insert(vl_key, vl_comp);
        }
    }

    let mut out: Vec<Component> = versioned.into_values().collect();
    out.sort_by(|l, r| {
        l.ecosystem
            .cmp(&r.ecosystem)
            .then_with(|| l.name.cmp(&r.name))
            .then_with(|| l.version.cmp(&r.version))
            .then_with(|| l.purl.cmp(&r.purl))
    });
    out
}

fn key_string(key: &ComponentKey) -> String {
    match key {
        ComponentKey::Purl(p) => format!("purl|{p}"),
        ComponentKey::NameVersion(e, n, v) => format!("nv|{e}|{n}|{}", v.as_deref().unwrap_or("")),
        ComponentKey::NameSha(n, s) => format!("ns|{n}|{s}"),
        ComponentKey::Fallback(f) => format!("fb|{f}"),
    }
}

/// The native ecosystems whose `pkg:generic` components may describe the same
/// physical C/C++ library under either label: `c` (a source-include observation)
/// and `generic` (a meson/cmake/vcpkg/Alire declaration).
fn is_native_ecosystem(eco: &str) -> bool {
    matches!(eco, "c" | "generic")
}

/// A normalized identity for a native (`pkg:generic`) component, so the
/// `c`-vs-`generic` ecosystem split and a dash/underscore name spelling don't
/// fragment one library into two components. `None` for non-native ecosystems.
fn native_identity(c: &Component) -> Option<String> {
    is_native_ecosystem(&c.ecosystem).then(|| crate::purl::normalize_native_name(&c.name))
}

/// Whether a versionless component should fold into the versioned candidate.
/// Native `pkg:generic` components match on normalized name across the `c`/
/// `generic` boundary (Bug #53); everything else keeps the strict
/// `(ecosystem, name)` match.
fn same_versionless_target(vl: &Component, cand: &Component) -> bool {
    if let (Some(a), Some(b)) = (native_identity(vl), native_identity(cand)) {
        return a == b;
    }
    vl.ecosystem == cand.ecosystem && vl.name == cand.name
}

/// Fold `incoming` into `existing`: union evidence; the higher rung's identity
/// fields (version/sha/license/purl) win so a lockfile pin upgrades a manifest range.
fn merge_into(existing: &mut Component, incoming: Component) {
    let existing_rung = top_rung(&existing.evidence);
    let incoming_rung = top_rung(&incoming.evidence);
    let incoming_wins = incoming_rung > existing_rung;
    if incoming_wins {
        existing.version = incoming.version;
        existing.purl = incoming.purl;
        if incoming.sha256.is_some() {
            existing.sha256 = incoming.sha256;
        }
        if incoming.license.is_some() {
            existing.license = incoming.license;
        }
        if incoming.group.is_some() {
            existing.group = incoming.group;
        }
        if !incoming.hashes.is_empty() {
            existing.hashes = incoming.hashes;
        }
    } else {
        if existing.sha256.is_none() {
            existing.sha256 = incoming.sha256;
        }
        if existing.license.is_none() {
            existing.license = incoming.license;
        }
        if existing.group.is_none() {
            existing.group = incoming.group;
        }
        if existing.hashes.is_empty() {
            existing.hashes = incoming.hashes;
        }
    }
    existing.evidence.extend(incoming.evidence);
    for h in incoming.runtime_harnesses {
        if !existing.runtime_harnesses.contains(&h) {
            existing.runtime_harnesses.push(h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Evidence, EvidenceKind};

    /// Minimal cargo component with purl set — used by merge_by_identity tests.
    fn pcomp(name: &str, version: &str) -> Component {
        Component {
            component_ref: String::new(),
            name: name.to_owned(),
            version: Some(version.to_owned()),
            ecosystem: "cargo".to_owned(),
            group: None,
            component_type: "source".to_owned(),
            supplier: None,
            license: None,
            purl: Some(format!("pkg:cargo/{name}@{version}")),
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "high".to_owned(),
            matching_method: "cargo_manifest".to_owned(),
            evidence: vec![Evidence::new(EvidenceKind::Declared, "Cargo.toml")],
            runtime_harnesses: Vec::new(),
        }
    }

    #[test]
    fn same_identity_manifest_and_lockfile_merge_into_one() {
        use crate::evidence::top_rung;
        let declared = Component {
            purl: Some("pkg:cargo/rand@0.8".to_owned()),
            version: Some("0.8".to_owned()),
            sha256: None,
            evidence: vec![Evidence::new(EvidenceKind::Declared, "Cargo.toml:3")],
            ..pcomp("rand", "0.8")
        };
        let resolved = Component {
            purl: Some("pkg:cargo/rand@0.8".to_owned()),
            version: Some("0.8.5".to_owned()),
            sha256: Some("34af...".to_owned()),
            evidence: vec![Evidence::new(
                EvidenceKind::Resolved,
                "Cargo.lock:[[package]] rand",
            )],
            ..pcomp("rand", "0.8.5")
        };
        let out = merge_by_identity(vec![declared, resolved]);
        assert_eq!(out.len(), 1);
        let c = &out[0];
        assert_eq!(c.version.as_deref(), Some("0.8.5"));
        assert_eq!(c.sha256.as_deref(), Some("34af..."));
        assert_eq!(c.evidence.len(), 2);
        assert_eq!(top_rung(&c.evidence), Some(EvidenceKind::Resolved));
    }

    #[test]
    fn distinct_identities_are_not_merged() {
        let out = merge_by_identity(vec![pcomp("a", "1.0"), pcomp("b", "1.0")]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn output_is_deterministically_sorted() {
        let out = merge_by_identity(vec![
            pcomp("b", "1.0"),
            pcomp("a", "2.0"),
            pcomp("a", "1.0"),
        ]);
        let names: Vec<_> = out
            .iter()
            .map(|c| (c.name.as_str(), c.version.as_deref()))
            .collect();
        assert_eq!(
            names,
            vec![("a", Some("1.0")), ("a", Some("2.0")), ("b", Some("1.0"))]
        );
    }

    /// Helper: a versionless (range-declared) cargo component — no version, name-only purl.
    fn vl_comp(name: &str) -> Component {
        Component {
            component_ref: String::new(),
            name: name.to_owned(),
            version: None,
            ecosystem: "cargo".to_owned(),
            group: None,
            component_type: "library".to_owned(),
            supplier: None,
            license: None,
            purl: Some(format!("pkg:cargo/{name}")),
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "high".to_owned(),
            matching_method: "cargo_manifest".to_owned(),
            evidence: vec![Evidence::new(EvidenceKind::Declared, "Cargo.toml")],
            runtime_harnesses: Vec::new(),
        }
    }

    #[test]
    fn versionless_merges_into_sole_versioned_of_same_ecosystem_name() {
        // A range-declared component (version=None, name-only purl) must fold
        // into the single versioned entry for the same (ecosystem, name), so the
        // merged component carries both Declared and Resolved evidence.
        let vl = vl_comp("idna");
        let versioned = pcomp("idna", "1.1.0");
        let out = merge_by_identity(vec![vl, versioned]);
        assert_eq!(out.len(), 1, "should merge into one component");
        let c = &out[0];
        assert_eq!(c.version.as_deref(), Some("1.1.0"));
        assert_eq!(c.purl.as_deref(), Some("pkg:cargo/idna@1.1.0"));
        // Both evidence entries preserved.
        assert_eq!(c.evidence.len(), 2);
        assert!(c.evidence.iter().any(|e| e.kind == EvidenceKind::Declared));
        assert!(c.evidence.iter().any(|e| e.kind == EvidenceKind::Declared));
    }

    #[test]
    fn versionless_stays_separate_when_two_versioned_entries_exist() {
        // If two different versions of the same crate are present, we cannot
        // know which one the versionless dep resolves to — leave it as-is.
        let vl = vl_comp("serde");
        let v1 = pcomp("serde", "1.0.0");
        let v2 = pcomp("serde", "2.0.0");
        let out = merge_by_identity(vec![vl, v1, v2]);
        assert_eq!(
            out.len(),
            3,
            "ambiguous: all three entries must remain separate"
        );
    }

    /// A native (C-source or meson/cmake) component with explicit ecosystem,
    /// version, purl and evidence rung — for the cross-ecosystem dedup test.
    #[allow(clippy::too_many_arguments)]
    fn native_comp(
        eco: &str,
        name: &str,
        version: Option<&str>,
        purl: Option<&str>,
        kind: EvidenceKind,
        src: &str,
    ) -> Component {
        Component {
            component_ref: String::new(),
            name: name.to_owned(),
            version: version.map(str::to_owned),
            ecosystem: eco.to_owned(),
            group: None,
            component_type: "library".to_owned(),
            supplier: None,
            license: None,
            purl: purl.map(str::to_owned),
            cpe: None,
            sha256: None,
            hashes: Vec::new(),
            identity_confidence: "low".to_owned(),
            matching_method: "test".to_owned(),
            evidence: vec![Evidence::new(kind, src)],
            runtime_harnesses: Vec::new(),
        }
    }

    #[test]
    fn native_versionless_folds_across_c_generic_and_dash_underscore() {
        // Bug #53: the same physical native library observed as a C-source include
        // (ecosystem "c", versioned, pkg:generic purl) AND as a meson dependency
        // (ecosystem "generic", versionless, no purl) must collapse to ONE
        // component. catch2: same spelling, different ecosystem. nlohmann: also a
        // dash/underscore name mismatch (nlohmann-json vs nlohmann_json).
        let c_catch = native_comp(
            "c",
            "catch2",
            Some("3.5.2"),
            Some("pkg:generic/catch2@3.5.2"),
            EvidenceKind::SourceObserved,
            "test.cpp:1",
        );
        let meson_catch = native_comp(
            "generic",
            "catch2",
            None,
            None,
            EvidenceKind::Declared,
            "meson.build:dependency(catch2)",
        );
        let c_nl = native_comp(
            "c",
            "nlohmann-json",
            Some("3.11.3"),
            Some("pkg:generic/nlohmann-json@3.11.3"),
            EvidenceKind::SourceObserved,
            "main.cpp:1",
        );
        let meson_nl = native_comp(
            "generic",
            "nlohmann_json",
            None,
            None,
            EvidenceKind::Declared,
            "meson.build:dependency(nlohmann_json)",
        );
        let out = merge_by_identity(vec![c_catch, meson_catch, c_nl, meson_nl]);
        assert_eq!(
            out.len(),
            2,
            "catch2 and nlohmann each collapse to one: {:?}",
            out.iter()
                .map(|c| (c.ecosystem.clone(), c.name.clone(), c.version.clone()))
                .collect::<Vec<_>>()
        );
        // Each surviving component carries BOTH evidence rungs.
        for c in &out {
            assert_eq!(
                c.evidence.len(),
                2,
                "{} must union the SourceObserved + Declared evidence",
                c.name
            );
            // The versioned (SourceObserved) identity wins.
            assert!(c.version.is_some(), "{} keeps the resolved version", c.name);
        }
    }

    #[test]
    fn distinct_native_libs_do_not_over_merge() {
        // Two genuinely different native libs must NOT fold together just because
        // both are pkg:generic across the c/generic boundary.
        let c_catch = native_comp(
            "c",
            "catch2",
            Some("3.5.2"),
            Some("pkg:generic/catch2@3.5.2"),
            EvidenceKind::SourceObserved,
            "test.cpp:1",
        );
        let meson_fmt = native_comp(
            "generic",
            "fmt",
            None,
            None,
            EvidenceKind::Declared,
            "meson.build:dependency(fmt)",
        );
        let out = merge_by_identity(vec![c_catch, meson_fmt]);
        assert_eq!(out.len(), 2, "catch2 and fmt are distinct libraries");
    }

    #[test]
    fn versioned_and_nameonly_purl_are_distinct_primary_keys() {
        // Identity-key grouping (primary pass) must NOT merge pkg:cargo/serde
        // with pkg:cargo/serde@1.0.0 — they are different Purl keys.
        // (The post-pass will merge them when exactly one versioned entry exists,
        // but identity_key alone must treat them as separate.)
        let vl = vl_comp("serde");
        let versioned = pcomp("serde", "1.0.0");
        assert_ne!(
            vl.identity_key(),
            versioned.identity_key(),
            "name-only purl key must differ from versioned purl key"
        );
        // Confirm purl-key strings differ (guards the key_string impl).
        assert_ne!(
            key_string(&vl.identity_key()),
            key_string(&versioned.identity_key())
        );
    }
}
